package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/imzyb/MiGate/internal/db"
)

func join(parts ...string) string { return strings.Join(parts, "") }

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
	if !strings.Contains(response.Body.String(), "面板登录") {
		t.Fatalf("expected login page without session cookie, got: %s", response.Body.String())
	}
}

func TestAuthAPIEndpointsRequireSession(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"))
	for _, path := range []string{"/api/inbounds", "/api/clients", "/api/xray/config", "/api/xray/apply", "/api/xray/status", "/api/singbox/config"} {
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
		t.Fatalf("removed legacy route should not remain public allowlisted, got %d", response.Code)
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
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong password, got %d: %s", response.Code, response.Body.String())
	}
}

func TestAuthLoginSucceedsWithValidCredentials(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"))

	body := `{"username":"admin","password":"secret"}`
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
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

func TestAuthLoginPageContainsLoginForm(t *testing.T) {
	router := NewRouter(WithAuth("admin", "secret"))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	router.ServeHTTP(response, req)
	body := response.Body.String()
	for _, want := range []string{"login", "password", "submit"} {
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
	loginReq := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(loginBody)))
	loginReq.Header.Set("Content-Type", "application/json")
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
	logoutReq := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	logoutReq.AddCookie(sessionCookie)
	router.ServeHTTP(logoutResp, logoutReq)
	if logoutResp.Code != http.StatusOK {
		t.Fatalf("expected 200 on logout, got %d", logoutResp.Code)
	}

	// Verify cookie is cleared (max-age = 0 or empty value)
	logoutCookies := logoutResp.Result().Cookies()
	var cleared bool
	for _, c := range logoutCookies {
		if c.Name == "migate_session" && c.MaxAge < 0 {
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
	logoutReq := httptest.NewRequest(http.MethodPost, "/migate/api/logout", nil)
	logoutReq.AddCookie(sessionCookie)
	router.ServeHTTP(logoutResp, logoutReq)

	for _, c := range logoutResp.Result().Cookies() {
		if c.Name == "migate_session" && c.MaxAge < 0 && c.Path == "/migate" {
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
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(`{"username":"admin","password":"secret"}`)))
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
	loginReq := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(`{"username":"admin","password":"secret"}`)))
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
	logoutReq := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
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

	var resp map[string]string
	if err := json.NewDecoder(afterLogout.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp["error"] != "session_revoked" {
		t.Fatalf("expected 'session_revoked' error, got %q", resp["error"])
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
		loginReq := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(`{"username":"admin","password":"secret"}`)))
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
	loginReq := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(`{"username":"admin","password":"secret"}`)))
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
	revokeReq := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/sessions/%.0f", firstID), nil)
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
	loginReq := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(`{"username":"admin","password":"secret"}`)))
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
	revokeReq := httptest.NewRequest(http.MethodDelete, "/api/sessions/99999", nil)
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
	loginReq := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(`{"username":"admin","password":"secret"}`)))
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
	logoutReq := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
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
