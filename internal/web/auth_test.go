package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/imzyb/MiGate/internal/db"
)

func join(parts ...string) string { return strings.Join(parts, "") }

func localLoginRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://127.0.0.1")
	req.Host = "127.0.0.1"
	req.RemoteAddr = "127.0.0.1:12345"
	return req
}

func localWriteRequest(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("Origin", "http://127.0.0.1")
	req.Host = "127.0.0.1"
	req.RemoteAddr = "127.0.0.1:12345"
	return req
}

func TestAuthIsDisabledByDefault(t *testing.T) {
	router := NewRouter()
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 with no auth, got %d", response.Code)
	}
}

func TestAuthShowsLoginPageForUnauthenticatedPanelRoot(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 login page without session cookie, got %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `id="root"`) {
		t.Fatalf("expected SPA shell without session cookie, got: %s", response.Body.String())
	}
}

func TestAuthAPIEndpointsRequireSession(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"))
	for _, path := range []string{"/api/inbounds", "/api/clients", "/api/xray/config", "/api/xray/apply", "/api/xray/status", "/api/singbox/config", "/api/singbox/status", "/api/singbox/diagnostics", "/api/singbox/version"} {
		response := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		router.ServeHTTP(response, req)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for %s without auth, got %d", path, response.Code)
		}
	}
}

func TestAuthRemovedLegacyRoutesAreNotPublicAllowlisted(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/"+join("vpn", "gate")+"/servers", nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("removed route should not remain public allowlisted, got %d", response.Code)
	}
}

func TestAuthLoginPagesArePublic(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"))
	for _, path := range []string{"/login", "/api/health"} {
		response := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		router.ServeHTTP(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("expected 200 for public path %s, got %d", path, response.Code)
		}
	}
}

func TestAuthLoginRejectsWrongCredentials(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"))

	body := `{"username":"admin","password":"wrong"}`
	response := httptest.NewRecorder()
	req := localLoginRequest(body)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong password, got %d: %s", response.Code, response.Body.String())
	}
}

func TestAuthLoginSucceedsWithValidCredentials(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"))

	body := `{"username":"admin","password":"secret"}`
	response := httptest.NewRecorder()
	req := localLoginRequest(body)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid login, got %d: %s", response.Code, response.Body.String())
	}

	// Response should set a session cookie
	cookies := response.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "migate_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session cookie 'migate_session' in response")
	}
	if sessionCookie.HttpOnly == false {
		t.Error("session cookie should be HttpOnly")
	}
	if sessionCookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("session cookie should use SameSite=Strict, got %v", sessionCookie.SameSite)
	}
	if sessionCookie.Value == "" {
		t.Error("session cookie value should not be empty")
	}

	// Use the session cookie to access a protected route
	protected := httptest.NewRecorder()
	protectedReq := httptest.NewRequest(http.MethodGet, "/", nil)
	protectedReq.AddCookie(sessionCookie)
	router.ServeHTTP(protected, protectedReq)
	if protected.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid session cookie, got %d: %s", protected.Code, protected.Body.String())
	}
}

func TestAuthLoginAcceptsHashedPassword(t *testing.T) {
	hashed, err := HashPanelPassword("secret")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	router := NewRouter(WithAuth("admin", hashed))
	response := httptest.NewRecorder()
	req := localLoginRequest(`{"username":"admin","password":"secret"}`)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 for hashed password login, got %d: %s", response.Code, response.Body.String())
	}
}

func TestAuthLoginMigratesPlaintextPasswordToHash(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/panel.json"
	if err := os.WriteFile(configPath, []byte(`{"panel_username":"admin","panel_password":"secret"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	router := NewRouter(WithAuth("admin", "secret"), WithConfigDir(dir))
	response := httptest.NewRecorder()
	req := localLoginRequest(`{"username":"admin","password":"secret"}`)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var saved map[string]interface{}
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	password, _ := saved["panel_password"].(string)
	if !IsPanelPasswordHash(password) || !VerifyPanelPassword(password, "secret") {
		t.Fatalf("expected migrated password hash, got %q", saved["panel_password"])
	}
}

func TestAuthLoginSetsSecureCookieForHTTPS(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"), WithTrustedProxyHeaders(true))
	response := httptest.NewRecorder()
	req := localLoginRequest(`{"username":"admin","password":"secret"}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://127.0.0.1")
	req.Header.Set("X-Forwarded-Proto", "https")
	router.ServeHTTP(response, req)

	var sessionCookie *http.Cookie
	for _, c := range response.Result().Cookies() {
		if c.Name == "migate_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session cookie")
	}
	if !sessionCookie.Secure {
		t.Fatal("HTTPS login should set Secure cookie")
	}
	if !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected cookie security attributes: %+v", sessionCookie)
	}
}

func TestAuthLoginSetsSecureCookieForDirectTLS(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"))
	response := httptest.NewRecorder()
	req := localLoginRequest(`{"username":"admin","password":"secret"}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://127.0.0.1")
	req.TLS = &tls.ConnectionState{}
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 for direct TLS login, got %d: %s", response.Code, response.Body.String())
	}
	sessionCookie := findSessionCookie(response.Result().Cookies())
	if sessionCookie == nil {
		t.Fatal("expected session cookie")
	}
	if !sessionCookie.Secure {
		t.Fatalf("direct TLS login should set Secure cookie: %+v", sessionCookie)
	}
}

func TestAuthLoginDoesNotTrustForwardedProtoByDefault(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"))
	response := httptest.NewRecorder()
	req := localLoginRequest(`{"username":"admin","password":"secret"}`)
	req.Header.Set("X-Forwarded-Proto", "https")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 login despite spoofed header, got %d: %s", response.Code, response.Body.String())
	}
	sessionCookie := findSessionCookie(response.Result().Cookies())
	if sessionCookie == nil {
		t.Fatal("expected session cookie")
	}
	if sessionCookie.Secure {
		t.Fatalf("default router must not trust spoofed X-Forwarded-Proto: %+v", sessionCookie)
	}
}

func TestAuthLoginAllowsSameOriginPublicHTTP(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"))
	response := httptest.NewRecorder()
	req := localLoginRequest(`{"username":"admin","password":"secret"}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://panel.example.com")
	req.Host = "panel.example.com"
	req.RemoteAddr = "203.0.113.10:44321"
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected same-origin public HTTP login to be allowed, got %d: %s", response.Code, response.Body.String())
	}
}

func TestAuthLoginAllowsSameOriginLoopbackHostFromPublicPeer(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"))
	response := httptest.NewRecorder()
	req := localLoginRequest(`{"username":"admin","password":"secret"}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://127.0.0.1:9999")
	req.Host = "127.0.0.1:9999"
	req.RemoteAddr = "203.0.113.10:44321"
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected same-origin loopback host login to be allowed, got %d: %s", response.Code, response.Body.String())
	}
}

func TestAuthLoginAllowsTrustedProxyHTTPS(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"), WithTrustedProxyHeaders(true))
	response := httptest.NewRecorder()
	req := localLoginRequest(`{"username":"admin","password":"secret"}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://panel.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Host = "panel.example.com"
	req.RemoteAddr = "203.0.113.10:44321"
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected trusted proxy HTTPS login to succeed, got %d: %s", response.Code, response.Body.String())
	}
	if cookie := findSessionCookie(response.Result().Cookies()); cookie == nil || !cookie.Secure {
		t.Fatalf("expected Secure cookie through trusted proxy, got %+v", cookie)
	}
}

func TestAuthCSRFAllowsPublicHostOrigin(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"), WithPublicHost("https://panel.example.com/app"), WithTrustedProxyHeaders(true))
	response := httptest.NewRecorder()
	req := localLoginRequest(`{"username":"admin","password":"secret"}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://panel.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Host = "127.0.0.1:9999"
	req.RemoteAddr = "203.0.113.10:44321"
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected public_host origin to be accepted, got %d: %s", response.Code, response.Body.String())
	}
}

func TestAuthCSRFAllowsPublicHostHttpsWithoutTrustedProxyHeaders(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"), WithPublicHost("https://migate.526566.xyz/panel"))
	response := httptest.NewRecorder()
	req := localLoginRequest(`{"username":"admin","password":"secret"}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://migate.526566.xyz")
	req.Host = "154.40.58.201:9999"
	req.RemoteAddr = "203.0.113.10:44321"
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected public_host https origin to be accepted without trusted proxy headers, got %d: %s", response.Code, response.Body.String())
	}
}

func TestAuthCSRFAllowsTrustedForwardedHostOrigin(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"), WithTrustedProxyHeaders(true))
	response := httptest.NewRecorder()
	req := localLoginRequest(`{"username":"admin","password":"secret"}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://panel.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "panel.example.com")
	req.Host = "127.0.0.1:9999"
	req.RemoteAddr = "203.0.113.10:44321"
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected trusted forwarded host origin to be accepted, got %d: %s", response.Code, response.Body.String())
	}
}

func TestAuthCSRFOriginPolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		origin string
		want   int
	}{
		{name: "same origin", origin: "http://127.0.0.1:9999", want: http.StatusOK},
		{name: "same host implicit default port", origin: "http://127.0.0.1", want: http.StatusForbidden},
		{name: "same host different port", origin: "http://127.0.0.1:4444", want: http.StatusForbidden},
		{name: "cross origin", origin: "http://evil.example", want: http.StatusForbidden},
		{name: "missing origin", origin: "", want: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router := NewRouter(WithAuth("admin", "secret"))
			resp := httptest.NewRecorder()
			req := localLoginRequest(`{"username":"admin","password":"secret"}`)
			req.Header.Set("Content-Type", "application/json")
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			} else {
				req.Header.Del("Origin")
			}
			req.Host = "127.0.0.1:9999"
			req.RemoteAddr = "127.0.0.1:54321"
			router.ServeHTTP(resp, req)
			if resp.Code != tc.want {
				t.Fatalf("expected %d, got %d: %s", tc.want, resp.Code, resp.Body.String())
			}
		})
	}
}

func TestAuthCSRFRejectionDoesNotConsumeLoginRateLimit(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"), WithTrustedProxyHeaders(true), WithLoginRateLimit(1, time.Minute))
	insecure := localLoginRequest(`{"username":"admin","password":"wrong"}`)
	insecure.Header.Set("Origin", "http://evil.example")
	insecure.Host = "panel.example.com"
	insecure.RemoteAddr = "203.0.113.10:44321"
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, insecure)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected cross-origin login to be rejected before rate limit, got %d: %s", resp.Code, resp.Body.String())
	}

	valid := localLoginRequest(`{"username":"admin","password":"secret"}`)
	valid.Header.Set("Origin", "https://panel.example.com")
	valid.Header.Set("X-Forwarded-Proto", "https")
	valid.Host = "panel.example.com"
	valid.RemoteAddr = "203.0.113.10:44321"
	ok := httptest.NewRecorder()
	router.ServeHTTP(ok, valid)
	if ok.Code != http.StatusOK {
		t.Fatalf("cross-origin request should not consume rate limit, got %d: %s", ok.Code, ok.Body.String())
	}
}

func TestAuthLoginRateLimitAndSuccessfulLoginClearsFailures(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"), WithLoginRateLimit(2, 20*time.Millisecond))
	for i := 0; i < 2; i++ {
		resp := httptest.NewRecorder()
		req := localLoginRequest(`{"username":"admin","password":"wrong"}`)
		req.RemoteAddr = "127.0.0.1:12345"
		router.ServeHTTP(resp, req)
		if resp.Code != http.StatusUnauthorized {
			t.Fatalf("expected failed login %d to return 401, got %d", i+1, resp.Code)
		}
	}
	limited := httptest.NewRecorder()
	limitedReq := localLoginRequest(`{"username":"admin","password":"secret"}`)
	limitedReq.RemoteAddr = "127.0.0.1:12345"
	router.ServeHTTP(limited, limitedReq)
	if limited.Code != http.StatusTooManyRequests {
		t.Fatalf("expected login to be rate limited, got %d: %s", limited.Code, limited.Body.String())
	}

	waitForLoginStatus(t, router, "127.0.0.1:12345", http.StatusOK, 200*time.Millisecond)

	afterReset := httptest.NewRecorder()
	afterResetReq := localLoginRequest(`{"username":"admin","password":"wrong"}`)
	afterResetReq.RemoteAddr = "127.0.0.1:12345"
	router.ServeHTTP(afterReset, afterResetReq)
	if afterReset.Code != http.StatusUnauthorized {
		t.Fatalf("successful login should clear failure state, got %d", afterReset.Code)
	}
}

func findSessionCookie(cookies []*http.Cookie) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == "migate_session" {
			return cookie
		}
	}
	return nil
}

func waitForLoginStatus(t *testing.T, router http.Handler, remoteAddr string, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastCode int
	var lastBody string
	for time.Now().Before(deadline) {
		resp := httptest.NewRecorder()
		req := localLoginRequest(`{"username":"admin","password":"secret"}`)
		req.RemoteAddr = remoteAddr
		router.ServeHTTP(resp, req)
		lastCode = resp.Code
		lastBody = resp.Body.String()
		if resp.Code == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected login status %d before timeout, last got %d: %s", want, lastCode, lastBody)
}

func TestAuthLoginRateLimitDoesNotTrustForwardedForByDefault(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"), WithLoginRateLimit(2, time.Minute))
	for i := 0; i < 2; i++ {
		resp := httptest.NewRecorder()
		req := localLoginRequest(`{"username":"admin","password":"wrong"}`)
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", i+1))
		req.RemoteAddr = "127.0.0.1:22345"
		router.ServeHTTP(resp, req)
		if resp.Code != http.StatusUnauthorized {
			t.Fatalf("expected failed login %d to return 401, got %d", i+1, resp.Code)
		}
	}
	limited := httptest.NewRecorder()
	limitedReq := localLoginRequest(`{"username":"admin","password":"secret"}`)
	limitedReq.Header.Set("X-Forwarded-For", "203.0.113.99")
	limitedReq.RemoteAddr = "127.0.0.1:22345"
	router.ServeHTTP(limited, limitedReq)
	if limited.Code != http.StatusTooManyRequests {
		t.Fatalf("expected spoofed X-Forwarded-For to remain rate limited, got %d", limited.Code)
	}
}

func TestAuthLoginPageContainsLoginForm(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	router.ServeHTTP(response, req)
	body := response.Body.String()
	for _, want := range []string{"migate", `id="root"`, `./assets/`} {
		if !strings.Contains(strings.ToLower(body), want) {
			t.Fatalf("login page missing %q: %s", want, body)
		}
	}
}

func TestAuthLogoutClearsSession(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"))

	// First login
	loginBody := `{"username":"admin","password":"secret"}`
	loginResp := httptest.NewRecorder()
	loginReq := localLoginRequest(loginBody)
	router.ServeHTTP(loginResp, loginReq)

	cookies := loginResp.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "migate_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("login should set session cookie")
	}

	// Then logout
	logoutResp := httptest.NewRecorder()
	logoutReq := localWriteRequest(http.MethodPost, "/api/logout")
	logoutReq.AddCookie(sessionCookie)
	router.ServeHTTP(logoutResp, logoutReq)
	if logoutResp.Code != http.StatusOK {
		t.Fatalf("expected 200 on logout, got %d", logoutResp.Code)
	}

	// Verify cookie is cleared with the same security attributes.
	logoutCookies := logoutResp.Result().Cookies()
	var cleared bool
	for _, c := range logoutCookies {
		if c.Name == "migate_session" && c.MaxAge < 0 && c.Path == "/" && c.SameSite == http.SameSiteStrictMode {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("logout should clear migate_session cookie")
	}
}

func TestAuthLogoutClearsSessionAtBasePath(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"), WithBasePath("/migate"))
	loginBody := `{"username":"admin","password":"secret"}`
	loginResp := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/migate/api/login", bytes.NewReader([]byte(loginBody)))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("Origin", "http://127.0.0.1")
	loginReq.Host = "127.0.0.1"
	loginReq.RemoteAddr = "127.0.0.1:12345"
	router.ServeHTTP(loginResp, loginReq)

	var sessionCookie *http.Cookie
	for _, c := range loginResp.Result().Cookies() {
		if c.Name == "migate_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil || sessionCookie.Path != "/migate" {
		t.Fatalf("login should set /migate session cookie, got %+v", sessionCookie)
	}

	logoutResp := httptest.NewRecorder()
	logoutReq := localWriteRequest(http.MethodPost, "/migate/api/logout")
	logoutReq.AddCookie(sessionCookie)
	router.ServeHTTP(logoutResp, logoutReq)

	for _, c := range logoutResp.Result().Cookies() {
		if c.Name == "migate_session" && c.MaxAge < 0 && c.Path == "/migate" && c.SameSite == http.SameSiteStrictMode {
			return
		}
	}
	t.Fatal("logout should clear migate_session cookie using the configured base path")
}

func TestAuthHealthEndpointDoesNotRequireAuthEvenWhenAuthEnabled(t *testing.T) {
	// This test is already in TestAuthLoginPagesArePublic, but let's be explicit
	router := NewRouter(WithAuth("admin", "secret"))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("health should be public, got %d", response.Code)
	}
}

func TestAuthSubscriptionEndpointIsPublic(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/some-uuid-here", nil)
	router.ServeHTTP(response, req)
	// Should be accessible without auth (clients need to fetch subscriptions)
	if response.Code == http.StatusUnauthorized {
		t.Fatal("/sub/{uuid} must be public, got 401")
	}
}

func TestAuthAPILoginIsPublic(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"))
	response := httptest.NewRecorder()
	req := localLoginRequest(`{"username":"admin","password":"secret"}`)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code == http.StatusUnauthorized {
		t.Fatal("/api/login must be public, got 401")
	}
}

// registerWithAuthTestImports ensures unused import doesn't cause issues
var _ = context.Background
var _ = json.Marshal

// TestAuthSessionRevocation verifies that logout adds the token to the
// blacklist and the revoked token is rejected by the auth middleware.
func TestAuthSessionRevocation(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := NewRouter(WithAuth("admin", "secret"), WithStore(store))

	// Login and get session cookie
	loginResp := httptest.NewRecorder()
	loginReq := localLoginRequest(`{"username":"admin","password":"secret"}`)
	loginReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(loginResp, loginReq)

	var sessionCookie *http.Cookie
	for _, c := range loginResp.Result().Cookies() {
		if c.Name == "migate_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("login should set session cookie")
	}

	// Verify we can access a protected route
	protected := httptest.NewRecorder()
	protectedReq := httptest.NewRequest(http.MethodGet, "/api/inbounds", nil)
	protectedReq.AddCookie(sessionCookie)
	router.ServeHTTP(protected, protectedReq)
	if protected.Code == http.StatusUnauthorized {
		t.Fatal("session should be valid after login")
	}

	// Logout (this revokes the session)
	logoutResp := httptest.NewRecorder()
	logoutReq := localWriteRequest(http.MethodPost, "/api/logout")
	logoutReq.AddCookie(sessionCookie)
	router.ServeHTTP(logoutResp, logoutReq)
	if logoutResp.Code != http.StatusOK {
		t.Fatalf("expected 200 on logout, got %d", logoutResp.Code)
	}

	// Verify the same cookie is now rejected (session_revoked)
	afterLogout := httptest.NewRecorder()
	afterLogoutReq := httptest.NewRequest(http.MethodGet, "/api/inbounds", nil)
	afterLogoutReq.AddCookie(sessionCookie)
	router.ServeHTTP(afterLogout, afterLogoutReq)
	if afterLogout.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for revoked session, got %d: %s", afterLogout.Code, afterLogout.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(afterLogout.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	errorObject, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected standard error object, got %#v", resp)
	}
	if errorObject["code"] != "session_revoked" {
		t.Fatalf("expected 'session_revoked' error code, got %q", errorObject["code"])
	}
}

// TestAuthSessionsEndpoint verifies GET /api/sessions lists active sessions.
func TestAuthSessionsEndpoint(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := NewRouter(WithAuth("admin", "secret"), WithStore(store))

	// Login twice to create two sessions
	login := func() *http.Cookie {
		loginResp := httptest.NewRecorder()
		loginReq := localLoginRequest(`{"username":"admin","password":"secret"}`)
		loginReq.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(loginResp, loginReq)
		for _, c := range loginResp.Result().Cookies() {
			if c.Name == "migate_session" {
				return c
			}
		}
		return nil
	}

	cookie1 := login()
	cookie2 := login()
	if cookie1 == nil || cookie2 == nil {
		t.Fatal("login should return session cookies")
	}

	// GET /api/sessions with a valid session
	sessionsResp := httptest.NewRecorder()
	sessionsReq := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	sessionsReq.AddCookie(cookie2)
	router.ServeHTTP(sessionsResp, sessionsReq)
	if sessionsResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", sessionsResp.Code)
	}

	var sessions []map[string]interface{}
	if err := json.NewDecoder(sessionsResp.Body).Decode(&sessions); err != nil {
		t.Fatalf("decode sessions: %v", err)
	}
	if len(sessions) < 2 {
		t.Fatalf("expected at least 2 sessions, got %d: %+v", len(sessions), sessions)
	}
	// Verify each session has the expected fields
	for _, s := range sessions {
		if s["id_prefix"] == nil || s["created_at"] == nil || s["last_used"] == nil {
			t.Fatalf("session missing expected fields: %+v", s)
		}
		prefix, ok := s["id_prefix"].(string)
		if !ok || len(prefix) != 8 {
			t.Fatalf("id_prefix should be 8-char hex string, got %q", s["id_prefix"])
		}
	}
}

func TestAuthLoginPrunesOldActiveSessions(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := NewRouter(WithAuth("admin", "secret"), WithStore(store))

	for i := 0; i < maxActiveSessions+2; i++ {
		loginResp := httptest.NewRecorder()
		loginReq := localLoginRequest(`{"username":"admin","password":"secret"}`)
		loginReq.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(loginResp, loginReq)
		if loginResp.Code != http.StatusOK {
			t.Fatalf("login %d expected 200, got %d: %s", i, loginResp.Code, loginResp.Body.String())
		}
	}

	sessions, err := store.ListActiveSessions(context.Background())
	if err != nil {
		t.Fatalf("ListActiveSessions: %v", err)
	}
	if len(sessions) != maxActiveSessions {
		t.Fatalf("expected %d active sessions, got %d", maxActiveSessions, len(sessions))
	}
}

func TestAuthRevokeOtherSessions(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := NewRouter(WithAuth("admin", "secret"), WithStore(store))
	login := func() *http.Cookie {
		loginResp := httptest.NewRecorder()
		loginReq := localLoginRequest(`{"username":"admin","password":"secret"}`)
		loginReq.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(loginResp, loginReq)
		if loginResp.Code != http.StatusOK {
			t.Fatalf("login expected 200, got %d: %s", loginResp.Code, loginResp.Body.String())
		}
		for _, c := range loginResp.Result().Cookies() {
			if c.Name == "migate_session" {
				return c
			}
		}
		t.Fatal("login should return session cookie")
		return nil
	}

	oldCookie := login()
	currentCookie := login()

	revokeResp := httptest.NewRecorder()
	revokeReq := localWriteRequest(http.MethodDelete, "/api/sessions/others")
	revokeReq.AddCookie(currentCookie)
	router.ServeHTTP(revokeResp, revokeReq)
	if revokeResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", revokeResp.Code, revokeResp.Body.String())
	}

	oldResp := httptest.NewRecorder()
	oldReq := httptest.NewRequest(http.MethodGet, "/api/inbounds", nil)
	oldReq.AddCookie(oldCookie)
	router.ServeHTTP(oldResp, oldReq)
	if oldResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected old session to be revoked, got %d", oldResp.Code)
	}

	currentResp := httptest.NewRecorder()
	currentReq := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	currentReq.AddCookie(currentCookie)
	router.ServeHTTP(currentResp, currentReq)
	if currentResp.Code != http.StatusOK {
		t.Fatalf("expected current session check 200, got %d", currentResp.Code)
	}
	var session map[string]interface{}
	if err := json.NewDecoder(currentResp.Body).Decode(&session); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if session["authenticated"] != true {
		t.Fatalf("expected current session to remain authenticated, got %+v", session)
	}
}

// TestAuthSessionRevokeByID verifies DELETE /api/sessions/{id} revokes a session.
func TestAuthSessionRevokeByID(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := NewRouter(WithAuth("admin", "secret"), WithStore(store))

	// Login
	loginResp := httptest.NewRecorder()
	loginReq := localLoginRequest(`{"username":"admin","password":"secret"}`)
	loginReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(loginResp, loginReq)

	var sessionCookie *http.Cookie
	for _, c := range loginResp.Result().Cookies() {
		if c.Name == "migate_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("login should set session cookie")
	}

	// List sessions to get the ID
	sessionsResp := httptest.NewRecorder()
	sessionsReq := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	sessionsReq.AddCookie(sessionCookie)
	router.ServeHTTP(sessionsResp, sessionsReq)

	var sessions []map[string]interface{}
	if err := json.NewDecoder(sessionsResp.Body).Decode(&sessions); err != nil {
		t.Fatalf("decode sessions: %v", err)
	}
	if len(sessions) == 0 {
		t.Fatal("expected at least 1 active session")
	}

	firstID := sessions[0]["id"].(float64)

	// Revoke the session by ID
	revokeResp := httptest.NewRecorder()
	revokeReq := localWriteRequest(http.MethodDelete, fmt.Sprintf("/api/sessions/%.0f", firstID))
	revokeReq.AddCookie(sessionCookie)
	router.ServeHTTP(revokeResp, revokeReq)
	if revokeResp.Code != http.StatusOK {
		t.Fatalf("expected 200 on revoke, got %d: %s", revokeResp.Code, revokeResp.Body.String())
	}

	// Original session should now be rejected
	afterRevoke := httptest.NewRecorder()
	afterRevokeReq := httptest.NewRequest(http.MethodGet, "/api/inbounds", nil)
	afterRevokeReq.AddCookie(sessionCookie)
	router.ServeHTTP(afterRevoke, afterRevokeReq)
	if afterRevoke.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after revoke, got %d", afterRevoke.Code)
	}
}

// TestAuthSessionRevokeByIDNotFound verifies 404 for unknown session ID.
func TestAuthSessionRevokeByIDNotFound(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := NewRouter(WithAuth("admin", "secret"), WithStore(store))

	// Login
	loginResp := httptest.NewRecorder()
	loginReq := localLoginRequest(`{"username":"admin","password":"secret"}`)
	loginReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(loginResp, loginReq)

	var sessionCookie *http.Cookie
	for _, c := range loginResp.Result().Cookies() {
		if c.Name == "migate_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("login should set session cookie")
	}

	// Revoke non-existent session
	revokeResp := httptest.NewRecorder()
	revokeReq := localWriteRequest(http.MethodDelete, "/api/sessions/99999")
	revokeReq.AddCookie(sessionCookie)
	router.ServeHTTP(revokeResp, revokeReq)
	if revokeResp.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", revokeResp.Code, revokeResp.Body.String())
	}
}

// TestAuthSessionHandlerDetectsRevokedSession verifies the /api/session
// endpoint returns revoked=true when the token is blacklisted.
func TestAuthSessionHandlerDetectsRevokedSession(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := NewRouter(WithAuth("admin", "secret"), WithStore(store))

	// Login
	loginResp := httptest.NewRecorder()
	loginReq := localLoginRequest(`{"username":"admin","password":"secret"}`)
	loginReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(loginResp, loginReq)

	var sessionCookie *http.Cookie
	for _, c := range loginResp.Result().Cookies() {
		if c.Name == "migate_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("login should set session cookie")
	}

	// Check session is valid
	sessionResp := httptest.NewRecorder()
	sessionReq := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	sessionReq.AddCookie(sessionCookie)
	router.ServeHTTP(sessionResp, sessionReq)

	var sessionData map[string]interface{}
	if err := json.NewDecoder(sessionResp.Body).Decode(&sessionData); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if sessionData["authenticated"] != true {
		t.Fatal("expected authenticated=true before revoke")
	}
	if sessionData["revoked"] == true {
		t.Fatal("expected revoked=false before revoke")
	}

	// Logout (revokes the session)
	logoutResp := httptest.NewRecorder()
	logoutReq := localWriteRequest(http.MethodPost, "/api/logout")
	logoutReq.AddCookie(sessionCookie)
	router.ServeHTTP(logoutResp, logoutReq)

	// Check session again - should show revoked
	sessionResp2 := httptest.NewRecorder()
	sessionReq2 := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	sessionReq2.AddCookie(sessionCookie)
	router.ServeHTTP(sessionResp2, sessionReq2)

	var sessionData2 map[string]interface{}
	if err := json.NewDecoder(sessionResp2.Body).Decode(&sessionData2); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if sessionData2["authenticated"] == true {
		t.Fatal("expected authenticated=false after revoke")
	}
	if sessionData2["revoked"] != true {
		t.Fatal("expected revoked=true after revoke")
	}
}

// TestHashToken verifies the BLAKE2b-256 hashing works correctly.
func TestHashToken(t *testing.T) {
	token := "test-token-value"
	hash := hashToken(token)
	if len(hash) != 64 { // 32 bytes = 64 hex chars
		t.Fatalf("expected 64-char hex hash, got %d-char: %s", len(hash), hash)
	}
	// Same input should produce same hash
	hash2 := hashToken(token)
	if hash != hash2 {
		t.Fatal("hashToken should be deterministic")
	}
	// Different input should produce different hash
	hash3 := hashToken("different-token")
	if hash == hash3 {
		t.Fatal("hashToken should produce different output for different input")
	}
}
