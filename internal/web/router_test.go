package web_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/imzyb/MiGate/internal/lockfile"
	"github.com/imzyb/MiGate/internal/paths"
	"github.com/imzyb/MiGate/internal/service/coreadmin"
	"github.com/imzyb/MiGate/internal/web"
	"github.com/imzyb/MiGate/internal/web/static"
)

func join(parts ...string) string { return strings.Join(parts, "") }

func webPackageSource(t *testing.T) string {
	return goPackageSource(t, ".")
}

func webAndCoreAdminSource(t *testing.T) string {
	return webPackageSource(t) + "\n" + goPackageSource(t, "../service/coreadmin")
}

func sourceBetween(t *testing.T, source, start, end string) string {
	t.Helper()
	startIndex := strings.Index(source, start)
	if startIndex < 0 {
		t.Fatalf("source missing start marker %q", start)
	}
	tail := source[startIndex:]
	if end == "" {
		return tail
	}
	endIndex := strings.Index(tail, end)
	if endIndex < 0 {
		t.Fatalf("source missing end marker %q after %q", end, start)
	}
	return tail[:endIndex]
}

func goPackageSource(t *testing.T, root string) string {
	t.Helper()
	var body strings.Builder
	err := fs.WalkDir(os.DirFS(root), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path == "static" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			return err
		}
		body.Write(source)
		body.WriteByte('\n')
		return nil
	})
	if err != nil {
		t.Fatalf("read package source %s: %v", root, err)
	}
	return body.String()
}

func webCoreInstallScript(t *testing.T, core string) string {
	t.Helper()
	plan, err := coreadmin.InstallPlan(core)
	if err != nil {
		t.Fatalf("core install plan %q: %v", core, err)
	}
	return plan.Script + "\n" + strings.Join(plan.Commands, "\n")
}

func TestRouterBackendSecurityContracts(t *testing.T) {
	body := webPackageSource(t)
	if strings.Contains(body, `exec.Command("bash", "-c"`) || strings.Contains(body, `exec.Command("sh", "-c"`) {
		t.Fatalf("web package must not execute shell strings via bash/sh -c")
	}
	if regexp.MustCompile(`tail",\s*"-n",\s*lines`).FindString(body) != "" && !strings.Contains(body, "maxXrayLogLines") {
		t.Fatalf("xray log line count must be clamped before passing to journalctl/tail")
	}
}

func TestSystemResourcesAPIReportsServerUsage(t *testing.T) {
	router := web.NewRouter()
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/api/system/resources", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("expected system resources 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var body map[string]float64
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode resources response: %v", err)
	}
	for _, key := range []string{"cpu_percent", "memory_total", "memory_used", "memory_percent", "disk_total", "disk_used", "disk_percent", "uptime_seconds"} {
		if _, ok := body[key]; !ok {
			t.Fatalf("resources response missing %s: %#v", key, body)
		}
	}
	if body["disk_total"] <= 0 {
		t.Fatalf("resources response should contain positive disk total: %#v", body)
	}
	if body["cpu_percent"] < 0 || body["cpu_percent"] > 100 || body["memory_percent"] < 0 || body["memory_percent"] > 100 || body["disk_percent"] < 0 || body["disk_percent"] > 100 {
		t.Fatalf("resource percentages should be clamped to 0..100: %#v", body)
	}

	post := httptest.NewRecorder()
	router.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/api/system/resources", nil))
	if post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected POST to be rejected, got %d", post.Code)
	}
}

func TestRouterServesEmbeddedSPAAndHealthAPI(t *testing.T) {
	router := web.NewRouter()

	page := httptest.NewRecorder()
	router.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))
	if page.Code != http.StatusOK {
		t.Fatalf("expected 200 for panel, got %d: %s", page.Code, page.Body.String())
	}
	body := page.Body.String()
	for _, want := range []string{"MiGate", `id="root"`, `./assets/`} {
		if !strings.Contains(body, want) {
			t.Fatalf("SPA index missing %q: %s", want, body)
		}
	}

	login := httptest.NewRecorder()
	router.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/login", nil))
	if login.Code != http.StatusOK || !strings.Contains(login.Body.String(), `id="root"`) {
		t.Fatalf("expected /login to serve SPA, got %d: %s", login.Code, login.Body.String())
	}

	health := httptest.NewRecorder()
	router.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("expected health 200, got %d: %s", health.Code, health.Body.String())
	}
	if !strings.Contains(health.Body.String(), `"status":"ok"`) || !strings.Contains(health.Body.String(), `"mode":"single-binary"`) {
		t.Fatalf("unexpected health body: %s", health.Body.String())
	}
}

func TestRouterSetsSecurityHeaders(t *testing.T) {
	router := web.NewRouter()
	for _, tc := range []struct {
		path  string
		https bool
	}{
		{path: "/"},
		{path: "/api/health", https: true},
	} {
		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		if tc.https {
			req.Header.Set("X-Forwarded-Proto", "https")
		}
		router.ServeHTTP(resp, req)
		for _, header := range []string{"X-Content-Type-Options", "Referrer-Policy", "Content-Security-Policy"} {
			if resp.Header().Get(header) == "" {
				t.Fatalf("%s response missing %s", tc.path, header)
			}
		}
		if resp.Header().Get("X-Frame-Options") != "DENY" {
			t.Fatalf("%s response should deny framing, got %q", tc.path, resp.Header().Get("X-Frame-Options"))
		}
		csp := resp.Header().Get("Content-Security-Policy")
		if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
			t.Fatalf("%s response should not allow inline scripts in CSP: %s", tc.path, csp)
		}
		if tc.path == "/" {
			nonce := firstCSPNonce(csp)
			if nonce == "" {
				t.Fatalf("%s response CSP should include a script nonce: %s", tc.path, csp)
			}
			if !strings.Contains(resp.Body.String(), `script nonce="`+nonce+`"`) {
				t.Fatalf("%s response should apply CSP nonce to inline scripts", tc.path)
			}
		}
		if tc.https && resp.Header().Get("Strict-Transport-Security") != "" {
			t.Fatalf("%s response should not trust X-Forwarded-Proto by default", tc.path)
		}
	}

	trusted := web.NewRouter(web.WithTrustedProxyHeaders(true))
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	trusted.ServeHTTP(resp, req)
	if resp.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("trusted proxy HTTPS response missing HSTS")
	}

	directTLS := web.NewRouter()
	tlsResp := httptest.NewRecorder()
	tlsReq := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	tlsReq.TLS = &tls.ConnectionState{}
	directTLS.ServeHTTP(tlsResp, tlsReq)
	if tlsResp.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("direct TLS response missing HSTS")
	}
}

type countingStatusController struct {
	calls int
}

func (c *countingStatusController) Status(ctx context.Context) web.XrayStatus {
	c.calls++
	return web.XrayStatus{Service: "xray", Status: "running", Installed: true, Managed: true, Version: "Xray test", CommandsExecuted: []string{}}
}

func (c *countingStatusController) Apply(ctx context.Context) web.XrayApplyResult {
	return web.XrayApplyResult{Applied: true, Status: "applied", Service: "xray", CommandsExecuted: []string{}}
}

func (c *countingStatusController) Version(ctx context.Context) string {
	return "Xray test"
}

func TestCoreStatusCachePreservesSecurityHeadersOnMissAndHit(t *testing.T) {
	controller := &countingStatusController{}
	router := web.NewRouter(web.WithXrayController(controller), web.WithCoreXrayListenerDiagnostics(func(context.Context) []web.CoreListenerDiagnostic {
		return []web.CoreListenerDiagnostic{}
	}))

	first := httptest.NewRecorder()
	router.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/api/xray/status", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("expected first status 200, got %d: %s", first.Code, first.Body.String())
	}
	assertSecurityHeaders(t, first.Header())
	if contentType := first.Header().Get("Content-Type"); !strings.Contains(contentType, "application/json") {
		t.Fatalf("expected first response JSON content type, got %q", contentType)
	}

	second := httptest.NewRecorder()
	router.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/api/xray/status", nil))
	if second.Code != http.StatusOK {
		t.Fatalf("expected cached status 200, got %d: %s", second.Code, second.Body.String())
	}
	assertSecurityHeaders(t, second.Header())
	if contentType := second.Header().Get("Content-Type"); !strings.Contains(contentType, "application/json") {
		t.Fatalf("expected cached response JSON content type, got %q", contentType)
	}
	if controller.calls != 1 {
		t.Fatalf("expected cached status response to avoid repeated controller call, got %d", controller.calls)
	}
}

func assertSecurityHeaders(t *testing.T, header http.Header) {
	t.Helper()
	for _, name := range []string{"X-Content-Type-Options", "Referrer-Policy", "X-Frame-Options", "Content-Security-Policy"} {
		if header.Get(name) == "" {
			t.Fatalf("response missing %s", name)
		}
	}
	if header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("unexpected X-Content-Type-Options: %q", header.Get("X-Content-Type-Options"))
	}
	if header.Get("Referrer-Policy") != "strict-origin-when-cross-origin" {
		t.Fatalf("unexpected Referrer-Policy: %q", header.Get("Referrer-Policy"))
	}
	if header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("unexpected X-Frame-Options: %q", header.Get("X-Frame-Options"))
	}
}

func firstCSPNonce(csp string) string {
	match := regexp.MustCompile(`'nonce-([^']+)'`).FindStringSubmatch(csp)
	if len(match) != 2 {
		return ""
	}
	return match[1]
}

func TestRouterServesViteAssets(t *testing.T) {
	entries, err := fs.ReadDir(static.Dist(), "assets")
	if err != nil {
		t.Fatalf("read embedded assets: %v", err)
	}
	var asset string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".js") {
			asset = entry.Name()
			break
		}
	}
	if asset == "" {
		t.Fatal("expected embedded Vite JS asset")
	}
	router := web.NewRouter()
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/assets/"+asset, nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("expected asset 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if cache := resp.Header().Get("Cache-Control"); cache != "public, max-age=31536000, immutable" {
		t.Fatalf("unexpected asset cache header: %q", cache)
	}
}

func TestRouterServesFaviconAssets(t *testing.T) {
	router := web.NewRouter()
	for _, tc := range []struct {
		path        string
		contentType string
	}{
		{path: "/favicon.svg", contentType: "image/svg"},
		{path: "/favicon.ico", contentType: "image/x-icon"},
	} {
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if resp.Code != http.StatusOK {
			t.Fatalf("expected %s 200, got %d: %s", tc.path, resp.Code, resp.Body.String())
		}
		if contentType := resp.Header().Get("Content-Type"); !strings.Contains(contentType, tc.contentType) {
			t.Fatalf("expected %s content type %q, got %q", tc.path, tc.contentType, contentType)
		}
		if cache := resp.Header().Get("Cache-Control"); cache != "public, max-age=31536000, immutable" {
			t.Fatalf("unexpected %s cache header: %q", tc.path, cache)
		}
	}
}

func TestRouterSPAFallbackAndAPISubIsolation(t *testing.T) {
	router := web.NewRouter()
	for _, path := range []string{"/inbounds", "/settings", "/login"} {
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, path, nil))
		if resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), `id="root"`) {
			t.Fatalf("expected %s to fallback to SPA, got %d: %s", path, resp.Code, resp.Body.String())
		}
	}
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/not-found"},
		{http.MethodPost, "/api/not-found"},
		{http.MethodGet, "/sub/not-found"},
		{http.MethodGet, "/assets/not-found.js"},
	} {
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, httptest.NewRequest(tc.method, tc.path, nil))
		if resp.Code != http.StatusNotFound {
			t.Fatalf("%s %s should not fallback to SPA, got %d", tc.method, tc.path, resp.Code)
		}
	}
}

func TestRouterBasePathServesSPAAssetsAndAPI(t *testing.T) {
	router := web.NewRouter(web.WithBasePath("/panel"))
	root := httptest.NewRecorder()
	router.ServeHTTP(root, httptest.NewRequest(http.MethodGet, "/panel", nil))
	if root.Code != http.StatusPermanentRedirect || root.Header().Get("Location") != "/panel/" {
		t.Fatalf("expected /panel to redirect to /panel/, got %d location=%q", root.Code, root.Header().Get("Location"))
	}
	for _, path := range []string{"/panel/", "/panel/login", "/panel/inbounds"} {
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, path, nil))
		if resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), `id="root"`) {
			t.Fatalf("expected %s to serve SPA, got %d: %s", path, resp.Code, resp.Body.String())
		}
		if !strings.Contains(resp.Body.String(), `window.__MIGATE_BASE_PATH__="/panel"`) {
			t.Fatalf("expected %s to inject SPA base path, got: %s", path, resp.Body.String())
		}
	}
	apiResp := httptest.NewRecorder()
	router.ServeHTTP(apiResp, httptest.NewRequest(http.MethodGet, "/panel/api/session", nil))
	if apiResp.Code != http.StatusOK {
		t.Fatalf("expected base-path API 200, got %d: %s", apiResp.Code, apiResp.Body.String())
	}
	favicon := httptest.NewRecorder()
	router.ServeHTTP(favicon, httptest.NewRequest(http.MethodGet, "/panel/favicon.svg", nil))
	if favicon.Code != http.StatusOK {
		t.Fatalf("expected base-path favicon 200, got %d: %s", favicon.Code, favicon.Body.String())
	}
	rootFavicon := httptest.NewRecorder()
	router.ServeHTTP(rootFavicon, httptest.NewRequest(http.MethodGet, "/favicon.svg", nil))
	if rootFavicon.Code != http.StatusOK {
		t.Fatalf("expected root favicon compatibility 200, got %d: %s", rootFavicon.Code, rootFavicon.Body.String())
	}
	outside := httptest.NewRecorder()
	router.ServeHTTP(outside, httptest.NewRequest(http.MethodGet, "/api/session", nil))
	if outside.Code != http.StatusNotFound {
		t.Fatalf("expected outside base path 404, got %d", outside.Code)
	}
}

func TestRouterBasePathLoginPathAcceptsPostForCompatibility(t *testing.T) {
	router := web.NewRouter(web.WithAuth("admin", "secret"), web.WithBasePath("/panel"))
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/panel/login", strings.NewReader(`{"username":"admin","password":"secret"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://127.0.0.1")
	req.Host = "127.0.0.1"
	req.RemoteAddr = "127.0.0.1:12345"
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected POST /panel/login to login, got %d: %s", resp.Code, resp.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, cookie := range resp.Result().Cookies() {
		if cookie.Name == "migate_session" {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil || sessionCookie.Path != "/panel" {
		t.Fatalf("expected /panel session cookie, got %+v", sessionCookie)
	}
}

func TestUpdateAPIStartsInstallerUpdateWithoutBlockingResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v1.1.0","html_url":"https://github.com/imzyb/MiGate/releases/tag/v1.1.0","name":"v1.1.0"}`))
	}))
	defer upstream.Close()

	router := web.NewRouter(web.WithVersion("v1.0.0"), web.WithUpdateCheckURL(upstream.URL))

	get := httptest.NewRecorder()
	router.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/api/update", nil))
	if get.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected GET /api/update 405, got %d", get.Code)
	}

	missingConfirm := httptest.NewRecorder()
	reqMissing := httptest.NewRequest(http.MethodPost, "/api/update", strings.NewReader(`{}`))
	reqMissing.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(missingConfirm, reqMissing)
	if missingConfirm.Code != http.StatusForbidden {
		t.Fatalf("expected POST /api/update without confirmation 403, got %d", missingConfirm.Code)
	}

	post := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/update", strings.NewReader(`{"confirm":true,"allow_system_changes":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(post, req)
	if post.Code != http.StatusOK {
		t.Fatalf("expected POST /api/update 200, got %d: %s", post.Code, post.Body.String())
	}
	for _, want := range []string{`"status":"updating"`, `"command":"/usr/local/bin/migate-install --update --yes"`} {
		if !strings.Contains(post.Body.String(), want) {
			t.Fatalf("update response missing %q: %s", want, post.Body.String())
		}
	}
}

func TestUpdateAPIDoesNotStartDefaultLatestWhenCurrentIsNewer(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v1.3.3","html_url":"https://github.com/imzyb/MiGate/releases/tag/v1.3.3","name":"v1.3.3"}`))
	}))
	defer upstream.Close()

	router := web.NewRouter(web.WithVersion("v1.3.5"), web.WithUpdateCheckURL(upstream.URL))
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/update", strings.NewReader(`{"confirm":true,"allow_system_changes":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusConflict {
		t.Fatalf("expected POST /api/update conflict, got %d: %s", resp.Code, resp.Body.String())
	}
	assertStandardAPIError(t, resp.Body.Bytes(), "update_not_available")
	if !strings.Contains(resp.Body.String(), "当前版本高于最新发布版本") {
		t.Fatalf("expected newer-current message, got %s", resp.Body.String())
	}
}

func TestUpdateCheckAPIReportsLatestRelease(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET update check, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.0","html_url":"https://github.com/imzyb/MiGate/releases/tag/v1.2.0","name":"v1.2.0"}`))
	}))
	defer upstream.Close()

	router := web.NewRouter(web.WithVersion("v1.1.0"), web.WithUpdateCheckURL(upstream.URL))
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/api/update/check", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("expected update check 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode update check: %v", err)
	}
	for _, want := range []string{`"current_version":"v1.1.0"`, `"latest_version":"v1.2.0"`, `"release_url":"https://github.com/imzyb/MiGate/releases/tag/v1.2.0"`, `"status":"ok"`} {
		if !strings.Contains(resp.Body.String(), want) {
			t.Fatalf("update check response missing %q: %s", want, resp.Body.String())
		}
	}
	if body["update_available"] != true {
		t.Fatalf("expected update_available true, got %#v", body["update_available"])
	}
}

func TestUpdateStatusAPIReportsState(t *testing.T) {
	router := web.NewRouter()
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/api/update/status", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("expected update status 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"status"`) {
		t.Fatalf("update status response missing status: %s", resp.Body.String())
	}
}

func TestUpdateStatusAPIReportsPersistentState(t *testing.T) {
	dir := t.TempDir()
	statusPath := filepath.Join(dir, "update-status.json")
	if err := os.WriteFile(statusPath, []byte(`{"status":"failed","current_version":"v1.0.0","target_version":"v1.0.1","message":"升级失败，已回滚，服务已恢复","rolled_back":true,"rollback_status":"restored","health_check":"systemctl is-active migate: active"}`), 0640); err != nil {
		t.Fatalf("write status: %v", err)
	}
	router := web.NewRouter(web.WithUpdateStatusPath(statusPath))
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/api/update/status", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("expected update status 200, got %d: %s", resp.Code, resp.Body.String())
	}
	for _, want := range []string{`"status":"failed"`, `"target_version":"v1.0.1"`, `"rolled_back":true`, `"rollback_status":"restored"`, `"health_check":"systemctl is-active migate: active"`} {
		if !strings.Contains(resp.Body.String(), want) {
			t.Fatalf("update persistent status response missing %q: %s", want, resp.Body.String())
		}
	}
}

func TestUpdateLogsAPIReportsRecentLogs(t *testing.T) {
	router := web.NewRouter()
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/api/update/logs?lines=20", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("expected update logs 200, got %d: %s", resp.Code, resp.Body.String())
	}
	for _, want := range []string{`"logs"`, `"/var/log/migate-update.log"`} {
		if !strings.Contains(resp.Body.String(), want) {
			t.Fatalf("update logs response missing %q: %s", want, resp.Body.String())
		}
	}
}

func TestUpdateAPIRunsInstallerOutsideMiGateServiceCgroup(t *testing.T) {
	body := goPackageSource(t, "../service/update")
	for _, want := range []string{
		`updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)`,
		`go s.runUpdateCommand(updateCtx, cancel)`,
		`RunOutput(ctx, "systemd-run"`,
		`unit := fmt.Sprintf("migate-update-%d-%d", s.getpid(), s.now().UnixNano())`,
		`"--unit="+unit`,
		`"--property=TimeoutSec=300"`,
		`logPath := s.logPath()`,
		`"--property=StandardOutput=append:"+logPath`,
		`"--property=StandardError=append:"+logPath`,
		`installerPath, "--update", "--yes"`,
		`/var/log/migate-update.log`,
		`func (s Service) ValidateUpdaterAvailable() error`,
		`s.geteuid()`,
		`s.lookPath()("systemd-run")`,
		`s.stat()("/run/systemd/system")`,
		`"journalctl", "-u", "migate-update", "-u", "migate-update-*"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("update handler missing detached updater contract %q", want)
		}
	}
	if strings.Contains(body, `"--replace"`) {
		t.Fatalf("update handler must not require systemd-run --replace; older systemd-run versions reject it")
	}
	if strings.Contains(body, `exec.Command("/usr/local/bin/migate-install", "--update").Run()`) {
		t.Fatalf("update handler must not run updater inside the migate service cgroup")
	}
}

func TestCoreInstallRunsOutsideMiGateServiceSandboxWhenSystemdIsAvailable(t *testing.T) {
	body := webPackageSource(t)
	for _, want := range []string{
		`runtimescript.Runner`,
		`RunBash(context.Background(), script)`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("core installer missing runtime adapter contract %q", want)
		}
	}
	for _, forbidden := range []string{
		`exec.LookPath("systemd-run")`,
		`exec.Command(`,
		`exec.CommandContext(`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("web package must not directly execute core scripts, found %q", forbidden)
		}
	}
	adapter := goPackageSource(t, "../runtime/script")
	for _, want := range []string{
		`LookPath("systemd-run")`,
		`Stat("/run/systemd/system")`,
		`exec.CommandContext(ctx, name, args...)`,
		`"systemd-run"`,
		`"--wait"`,
		`"--pipe"`,
		`"--property=User=root"`,
		`"--property=TimeoutSec="+systemdTimeoutSec(timeout)`,
		`"bash"`,
		`"-s"`,
	} {
		if !strings.Contains(adapter, want) {
			t.Fatalf("runtime script adapter missing detached root execution contract %q", want)
		}
	}
}

func TestSocks5PoolEndpointReportsCacheMetadata(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"proxy":"socks5://user:pass@127.0.0.1:65000","country":"US","country_en":"United States"}]`))
	}))
	defer upstream.Close()
	router := web.NewRouter(web.WithSocks5PoolURL(upstream.URL))
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/api/outbounds/socks5-pool", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("expected socks5 pool 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["cache_status"] == nil || body["cache_updated_at"] == nil {
		t.Fatalf("SOCKS5 pool response must expose cache metadata: %s", resp.Body.String())
	}
}

func TestSessionAPIReportsAuthUser(t *testing.T) {
	router := web.NewRouter(web.WithAuth("sam", "secret"))

	unauth := httptest.NewRecorder()
	router.ServeHTTP(unauth, httptest.NewRequest(http.MethodGet, "/api/session", nil))
	if unauth.Code != http.StatusOK {
		t.Fatalf("expected public session endpoint 200, got %d: %s", unauth.Code, unauth.Body.String())
	}
	if !strings.Contains(unauth.Body.String(), `"authenticated":false`) || !strings.Contains(unauth.Body.String(), `"auth_enabled":true`) {
		t.Fatalf("unexpected unauthenticated session body: %s", unauth.Body.String())
	}

	login := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"sam","password":"secret"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://127.0.0.1")
	req.Host = "127.0.0.1"
	req.RemoteAddr = "127.0.0.1:12345"
	router.ServeHTTP(login, req)
	if login.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", login.Code, login.Body.String())
	}

	sess := httptest.NewRecorder()
	sessReq := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	for _, c := range login.Result().Cookies() {
		sessReq.AddCookie(c)
	}
	router.ServeHTTP(sess, sessReq)
	if sess.Code != http.StatusOK {
		t.Fatalf("expected authenticated session 200, got %d: %s", sess.Code, sess.Body.String())
	}
	for _, want := range []string{`"authenticated":true`, `"auth_enabled":true`, `"username":"sam"`} {
		if !strings.Contains(sess.Body.String(), want) {
			t.Fatalf("session response missing %q: %s", want, sess.Body.String())
		}
	}
}

func TestRestartEndpoint(t *testing.T) {
	t.Run("POST returns restarting status", func(t *testing.T) {
		router := web.NewRouter()
		response := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/restart", strings.NewReader(`{"confirm":true,"allow_system_changes":true}`))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), "restarting") {
			t.Fatalf("expected restarting status, got %s", response.Body.String())
		}
	})
	t.Run("GET returns 405", func(t *testing.T) {
		router := web.NewRouter()
		response := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/restart", nil)
		router.ServeHTTP(response, req)
		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", response.Code)
		}
	})
}

func TestAPIErrorResponsesUseJSONContentType(t *testing.T) {
	withTempApplyLock(t)
	unlock, err := lockfile.TryAcquire(paths.ApplyLock)
	if err != nil {
		t.Fatalf("acquire apply lock: %v", err)
	}
	defer unlock()
	router := web.NewRouter()
	for _, tc := range []struct {
		method string
		path   string
		body   string
		status int
		error  string
	}{
		{http.MethodPost, "/api/xray/apply", `{"confirm":true}`, http.StatusForbidden, "confirmation_required"},
		{http.MethodPost, "/api/xray/apply", `{bad`, http.StatusBadRequest, "invalid_json"},
		{http.MethodGet, "/api/restart", "", http.StatusMethodNotAllowed, "method_not_allowed"},
		{http.MethodGet, "/api/xray/validate", "", http.StatusOK, ""},
		{http.MethodPost, "/api/xray/validate", "", http.StatusMethodNotAllowed, "method_not_allowed"},
		{http.MethodPost, "/api/singbox/validate", "", http.StatusMethodNotAllowed, "method_not_allowed"},
		{http.MethodGet, "/api/xray/config", "", http.StatusServiceUnavailable, "store_unavailable"},
		{http.MethodPost, "/api/xray/apply", `{"confirm":true,"allow_system_changes":true}`, http.StatusConflict, "apply_locked"},
	} {
		response := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		if tc.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		router.ServeHTTP(response, req)
		if response.Code != tc.status {
			t.Fatalf("%s %s expected %d, got %d: %s", tc.method, tc.path, tc.status, response.Code, response.Body.String())
		}
		if contentType := response.Header().Get("Content-Type"); !strings.Contains(contentType, "application/json") {
			t.Fatalf("%s %s expected JSON content type, got %q", tc.method, tc.path, contentType)
		}
		if tc.error == "" {
			continue
		}
		assertStandardAPIError(t, response.Body.Bytes(), tc.error)
	}
}

func assertStandardAPIError(t *testing.T, body []byte, wantCode string) {
	t.Helper()
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("error response should be JSON: %v body=%s", err, string(body))
	}
	detail, ok := payload["error"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected standard error object, got %#v", payload)
	}
	if detail["code"] != wantCode {
		t.Fatalf("expected error.code %q, got %#v", wantCode, detail)
	}
	message, ok := detail["message"].(string)
	if !ok || message == "" {
		t.Fatalf("expected error.message for %q, got %#v", wantCode, detail)
	}
}

func TestAPIErrorContractFields(t *testing.T) {
	router := web.NewRouter()
	for _, tc := range []struct {
		method string
		path   string
		body   string
		status int
		code   string
	}{
		{http.MethodPost, "/api/update", `{bad`, http.StatusBadRequest, "invalid_json"},
		{http.MethodGet, "/api/update", "", http.StatusMethodNotAllowed, "method_not_allowed"},
		{http.MethodPost, "/api/update", `{}`, http.StatusForbidden, "confirmation_required"},
		{http.MethodGet, "/api/xray/config", "", http.StatusServiceUnavailable, "store_unavailable"},
	} {
		response := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		if tc.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		router.ServeHTTP(response, req)
		if response.Code != tc.status {
			t.Fatalf("%s %s expected %d, got %d: %s", tc.method, tc.path, tc.status, response.Code, response.Body.String())
		}
		assertStandardAPIError(t, response.Body.Bytes(), tc.code)
	}
}

func TestAPIApplyLockedErrorContract(t *testing.T) {
	withTempApplyLock(t)
	unlock, err := lockfile.TryAcquire(paths.ApplyLock)
	if err != nil {
		t.Fatalf("acquire apply lock: %v", err)
	}
	defer unlock()
	router := web.NewRouter()
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/xray/apply", strings.NewReader(`{"confirm":true,"allow_system_changes":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusConflict {
		t.Fatalf("expected locked apply to return 409, got %d: %s", response.Code, response.Body.String())
	}
	assertStandardAPIError(t, response.Body.Bytes(), "apply_locked")
	var payload map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	detail := payload["error"].(map[string]interface{})
	fields, ok := detail["fields"].(map[string]interface{})
	if !ok || fields["lock_path"] == "" {
		t.Fatalf("expected lock_path in error.fields, got %#v", payload)
	}
}

func TestRouteContractsAreRegisteredAndEnforced(t *testing.T) {
	contracts := map[string]web.RouteContract{}
	for _, route := range web.RouteContracts() {
		key := route.Method + " " + route.Path
		if _, exists := contracts[key]; exists {
			t.Fatalf("duplicate route contract %s", key)
		}
		contracts[key] = route
	}
	for _, want := range []web.RouteContract{
		{Method: http.MethodPost, Path: "/api/login", Auth: web.AuthPublic, CSRF: web.CSRFRequired},
		{Method: http.MethodGet, Path: "/api/session", Auth: web.AuthPublic, CSRF: web.CSRFNotRequired},
		{Method: http.MethodGet, Path: "/api/settings", Auth: web.AuthRequired, CSRF: web.CSRFNotRequired},
		{Method: http.MethodPut, Path: "/api/settings", Auth: web.AuthRequired, CSRF: web.CSRFRequired},
		{Method: http.MethodGet, Path: "/api/version", Auth: web.AuthRequired, CSRF: web.CSRFNotRequired},
		{Method: http.MethodGet, Path: "/api/health", Auth: web.AuthPublic, CSRF: web.CSRFNotRequired},
		{Method: http.MethodGet, Path: "/api/xray/status", Auth: web.AuthRequired, CSRF: web.CSRFNotRequired},
		{Method: http.MethodPost, Path: "/api/xray/apply", Auth: web.AuthRequired, CSRF: web.CSRFRequired},
		{Method: http.MethodPost, Path: "/api/xray/install", Auth: web.AuthRequired, CSRF: web.CSRFRequired},
		{Method: http.MethodPost, Path: "/api/xray/delete", Auth: web.AuthRequired, CSRF: web.CSRFRequired},
		{Method: http.MethodPost, Path: "/api/xray/restart", Auth: web.AuthRequired, CSRF: web.CSRFRequired},
		{Method: http.MethodPost, Path: "/api/xray/stop", Auth: web.AuthRequired, CSRF: web.CSRFRequired},
		{Method: http.MethodGet, Path: "/api/singbox/status", Auth: web.AuthRequired, CSRF: web.CSRFNotRequired},
		{Method: http.MethodPost, Path: "/api/singbox/apply", Auth: web.AuthRequired, CSRF: web.CSRFRequired},
		{Method: http.MethodPost, Path: "/api/singbox/install", Auth: web.AuthRequired, CSRF: web.CSRFRequired},
		{Method: http.MethodPost, Path: "/api/singbox/delete", Auth: web.AuthRequired, CSRF: web.CSRFRequired},
		{Method: http.MethodPost, Path: "/api/singbox/restart", Auth: web.AuthRequired, CSRF: web.CSRFRequired},
		{Method: http.MethodPost, Path: "/api/singbox/stop", Auth: web.AuthRequired, CSRF: web.CSRFRequired},
		{Method: http.MethodGet, Path: "/api/update/check", Auth: web.AuthRequired, CSRF: web.CSRFNotRequired},
		{Method: http.MethodPost, Path: "/api/update", Auth: web.AuthRequired, CSRF: web.CSRFRequired},
		{Method: http.MethodGet, Path: "/api/cert/status", Auth: web.AuthRequired, CSRF: web.CSRFNotRequired},
		{Method: http.MethodPost, Path: "/api/cert/issue", Auth: web.AuthRequired, CSRF: web.CSRFRequired},
	} {
		got, ok := contracts[want.Method+" "+want.Path]
		if !ok {
			t.Fatalf("route contract missing %s %s", want.Method, want.Path)
		}
		if got.Auth != want.Auth || got.CSRF != want.CSRF || got.Handler == "" {
			t.Fatalf("route contract mismatch for %s %s: %#v", want.Method, want.Path, got)
		}
	}
}

func TestDangerousRouteContractsAndCSRF(t *testing.T) {
	dangerous := map[string]bool{
		"POST /api/xray/apply":        true,
		"POST /api/xray/install":      true,
		"POST /api/xray/uninstall":    true,
		"POST /api/xray/delete":       true,
		"POST /api/xray/restart":      true,
		"POST /api/xray/stop":         true,
		"POST /api/singbox/apply":     true,
		"POST /api/singbox/install":   true,
		"POST /api/singbox/uninstall": true,
		"POST /api/singbox/delete":    true,
		"POST /api/singbox/restart":   true,
		"POST /api/singbox/stop":      true,
		"POST /api/update":            true,
		"POST /api/cert/issue":        true,
		"POST /api/certificates":      true,
		"POST /api/certificates/":     true,
		"POST /api/restart":           true,
	}
	declared := map[string]web.RouteContract{}
	for _, route := range web.RouteContracts() {
		if !strings.HasPrefix(route.Path, "/api/") {
			t.Fatalf("API route contract path must start with /api/: %#v", route)
		}
		switch route.Method {
		case http.MethodGet:
			if route.CSRF != web.CSRFNotRequired {
				t.Fatalf("GET API route must not require CSRF: %#v", route)
			}
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			if route.CSRF != web.CSRFRequired {
				t.Fatalf("write API route must require CSRF: %#v", route)
			}
		}
		key := route.Method + " " + route.Path
		if dangerous[key] {
			declared[key] = route
			if route.Method != http.MethodPost {
				t.Fatalf("dangerous route %s must be POST, got %s", route.Path, route.Method)
			}
			if route.CSRF != web.CSRFRequired {
				t.Fatalf("dangerous route %s must require CSRF, got %s", route.Path, route.CSRF)
			}
		}
	}
	for key := range dangerous {
		if _, ok := declared[key]; !ok {
			t.Fatalf("dangerous route %s is not declared in route contracts", key)
		}
	}
	router := web.NewRouter(web.WithAuth("admin", "secret"))
	login := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"secret"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("Origin", "http://127.0.0.1")
	loginReq.Host = "127.0.0.1"
	loginReq.RemoteAddr = "127.0.0.1:12345"
	router.ServeHTTP(login, loginReq)
	if login.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", login.Code, login.Body.String())
	}
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/update", strings.NewReader(`{"confirm":true,"allow_system_changes":true}`))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range login.Result().Cookies() {
		req.AddCookie(cookie)
	}
	router.ServeHTTP(response, req)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "csrf_origin_mismatch") {
		t.Fatalf("dangerous route must be blocked by CSRF without same-origin header, got %d: %s", response.Code, response.Body.String())
	}
}

func TestAuthAndCSRFMiddlewareFollowRouteContracts(t *testing.T) {
	router := web.NewRouter(web.WithAuth("admin", "secret"))

	publicSession := httptest.NewRecorder()
	router.ServeHTTP(publicSession, httptest.NewRequest(http.MethodGet, "/api/session", nil))
	if publicSession.Code != http.StatusOK {
		t.Fatalf("public route contract should allow unauthenticated session read, got %d: %s", publicSession.Code, publicSession.Body.String())
	}

	protectedVersion := httptest.NewRecorder()
	router.ServeHTTP(protectedVersion, httptest.NewRequest(http.MethodGet, "/api/version", nil))
	if protectedVersion.Code != http.StatusUnauthorized {
		t.Fatalf("required-auth route contract should reject unauthenticated version read, got %d: %s", protectedVersion.Code, protectedVersion.Body.String())
	}

	login := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"secret"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("Origin", "http://127.0.0.1")
	loginReq.Host = "127.0.0.1"
	loginReq.RemoteAddr = "127.0.0.1:12345"
	router.ServeHTTP(login, loginReq)
	if login.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", login.Code, login.Body.String())
	}

	update := httptest.NewRecorder()
	updateReq := httptest.NewRequest(http.MethodPost, "/api/update", strings.NewReader(`{"confirm":true,"allow_system_changes":true}`))
	updateReq.Header.Set("Content-Type", "application/json")
	for _, cookie := range login.Result().Cookies() {
		updateReq.AddCookie(cookie)
	}
	router.ServeHTTP(update, updateReq)
	if update.Code != http.StatusForbidden {
		t.Fatalf("CSRF-required route contract should reject missing origin, got %d: %s", update.Code, update.Body.String())
	}
	assertStandardAPIError(t, update.Body.Bytes(), "csrf_origin_mismatch")
}

func TestReadOnlyRouteContractsUseGET(t *testing.T) {
	for _, route := range web.RouteContracts() {
		if route.Method == http.MethodGet && route.CSRF != web.CSRFNotRequired {
			t.Fatalf("GET route must not require CSRF: %#v", route)
		}
	}
	router := web.NewRouter()
	for _, path := range []string{"/api/health", "/api/version", "/api/update/status", "/api/update/logs"} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s should be accessible, got %d: %s", path, response.Code, response.Body.String())
		}
	}
}

func TestRouteContractsCoverCriticalAPIBehavior(t *testing.T) {
	contracts := map[string]web.RouteContract{}
	for _, route := range web.RouteContracts() {
		contracts[route.Method+" "+route.Path] = route
	}
	for _, want := range []web.RouteContract{
		{Method: http.MethodPost, Path: "/api/login", Auth: web.AuthPublic, CSRF: web.CSRFRequired},
		{Method: http.MethodGet, Path: "/api/session", Auth: web.AuthPublic, CSRF: web.CSRFNotRequired},
		{Method: http.MethodPost, Path: "/api/xray/apply", Auth: web.AuthRequired, CSRF: web.CSRFRequired},
		{Method: http.MethodPost, Path: "/api/singbox/install", Auth: web.AuthRequired, CSRF: web.CSRFRequired},
		{Method: http.MethodPut, Path: "/api/settings", Auth: web.AuthRequired, CSRF: web.CSRFRequired},
		{Method: http.MethodGet, Path: "/api/service/status", Auth: web.AuthRequired, CSRF: web.CSRFNotRequired},
	} {
		got, ok := contracts[want.Method+" "+want.Path]
		if !ok {
			t.Fatalf("route contract missing %s %s", want.Method, want.Path)
		}
		if got.Auth != want.Auth || got.CSRF != want.CSRF || got.Handler == "" {
			t.Fatalf("route contract mismatch for %s %s: %#v", want.Method, want.Path, got)
		}
	}
}

func TestRouteContractsMatchRegisteredRouterPaths(t *testing.T) {
	configDir := t.TempDir()
	if err := os.WriteFile(configDir+"/panel.json", []byte(`{"panel_port":9999,"database_path":"/var/lib/migate/migate.db"}`), 0o600); err != nil {
		t.Fatalf("write panel config: %v", err)
	}
	router := web.NewRouter(web.WithConfigDir(configDir))
	checked := map[string]bool{}
	for _, route := range web.RouteContracts() {
		if !strings.HasPrefix(route.Path, "/api/") {
			t.Fatalf("route contract path must start with /api/: %#v", route)
		}
		if checked[route.Path] {
			continue
		}
		checked[route.Path] = true
		response := httptest.NewRecorder()
		testPath := route.Path
		if strings.HasSuffix(testPath, "/") {
			testPath += "1"
		}
		req := httptest.NewRequest(http.MethodOptions, testPath, nil)
		router.ServeHTTP(response, req)
		if response.Code == http.StatusNotFound {
			t.Fatalf("route contract %s %s is not registered", route.Method, route.Path)
		}
	}
	for _, critical := range []string{
		"/api/login",
		"/api/session",
		"/api/inbounds",
		"/api/outbounds",
		"/api/routing-rules",
		"/api/xray/apply",
		"/api/xray/install",
		"/api/singbox/apply",
		"/api/singbox/install",
		"/api/settings",
		"/api/update",
		"/api/restart",
	} {
		if !routeContractPathExists(critical) {
			t.Fatalf("critical registered route %s must be represented in RouteContracts", critical)
		}
	}
}

func routeContractPathExists(path string) bool {
	for _, route := range web.RouteContracts() {
		if route.Path == path {
			return true
		}
	}
	return false
}

func TestRouterDoesNotServeRemovedHeavyRoutes(t *testing.T) {
	router := web.NewRouter()
	for _, path := range []string{"/api/remote/readiness", "/api/leak-check", "/api/egress/status", "/api/" + join("open", "vpn") + "/status", "/api/proxy/status"} {
		response := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		router.ServeHTTP(response, req)
		if response.Code != http.StatusNotFound {
			t.Fatalf("removed heavy route %s should be 404, got %d", path, response.Code)
		}
	}
}

func TestCoreInstallUninstallAPIsRequireExplicitSystemChangeConfirmation(t *testing.T) {
	router := web.NewRouter()
	for _, tc := range []struct {
		path string
	}{
		{"/api/xray/apply"},
		{"/api/xray/install"},
		{"/api/xray/uninstall"},
		{"/api/xray/delete"},
		{"/api/xray/restart"},
		{"/api/xray/stop"},
		{"/api/singbox/apply"},
		{"/api/singbox/install"},
		{"/api/singbox/uninstall"},
		{"/api/singbox/delete"},
		{"/api/singbox/restart"},
		{"/api/singbox/stop"},
		{"/api/cert/issue"},
		{"/api/certificates"},
		{"/api/certificates/import"},
		{"/api/certificates/renew-due"},
		{"/api/certificates/1/apply"},
		{"/api/certificates/1/delete"},
		{"/api/update"},
		{"/api/restart"},
	} {
		response := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(`{"confirm":true}`))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(response, req)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s without allow_system_changes = %d, want 403", tc.path, response.Code)
		}
		assertStandardAPIError(t, response.Body.Bytes(), "confirmation_required")
	}
}

func TestCoreInstallAPIsRequireExplicitSystemChangeConfirmation(t *testing.T) {
	router := web.NewRouter(web.WithCoreScriptRunner(func(script string) ([]byte, error) {
		t.Fatalf("runner must not be called without confirmation")
		return nil, nil
	}))
	for _, path := range []string{"/api/xray/install", "/api/singbox/install"} {
		response := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"confirm":true}`))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(response, req)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s without allow_system_changes = %d, want 403", path, response.Code)
		}
		assertStandardAPIError(t, response.Body.Bytes(), "confirmation_required")
		if !strings.Contains(response.Body.String(), `"commands_executed":[]`) {
			t.Fatalf("%s rejection missing commands_executed: %s", path, response.Body.String())
		}
	}
}

func TestCoreInstallSuccessReturnsStructuredActionResult(t *testing.T) {
	router := web.NewRouter(web.WithCoreScriptRunner(func(script string) ([]byte, error) {
		if strings.TrimSpace(script) == "" {
			t.Fatal("runner received empty script")
		}
		return []byte("sing-box 1.13.13"), nil
	}))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/singbox/install", strings.NewReader(`{"confirm":true,"allow_system_changes":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	for _, want := range []string{`"core":"singbox"`, `"status":"installed"`, `"output":"sing-box 1.13.13"`, `"commands_executed":[`, `"download sing-box release"`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("install success response missing %q: %s", want, response.Body.String())
		}
	}
	if strings.Contains(response.Body.String(), `"error"`) {
		t.Fatalf("install success response must not include error: %s", response.Body.String())
	}
}

func TestCoreServiceControlAPIsRunExpectedSystemctlCommands(t *testing.T) {
	for _, tc := range []struct {
		path    string
		command string
		core    string
		status  string
	}{
		{"/api/xray/restart", "systemctl restart migate-xray", "xray", "restarted"},
		{"/api/xray/stop", "systemctl stop migate-xray", "xray", "stopped"},
		{"/api/singbox/restart", "systemctl restart migate-sing-box", "singbox", "restarted"},
		{"/api/singbox/stop", "systemctl stop migate-sing-box", "singbox", "stopped"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			var scriptSeen string
			router := web.NewRouter(web.WithCoreScriptRunner(func(script string) ([]byte, error) {
				scriptSeen = script
				if !strings.Contains(script, `command -v systemctl`) || !strings.Contains(script, `[ ! -d /run/systemd/system ]`) {
					t.Fatalf("service control script must fail clearly when systemd is unavailable: %s", script)
				}
				if !strings.Contains(script, `systemctl show `) || !strings.Contains(script, `--property=LoadState --value`) {
					t.Fatalf("service control script must check unit load state first: %s", script)
				}
				if tc.status == "stopped" && (!strings.Contains(script, `systemctl is-active `) || !strings.Contains(script, `systemctl reset-failed `) || !strings.Contains(script, `already stopped`)) {
					t.Fatalf("stop script must handle inactive or missing services idempotently: %s", script)
				}
				if !strings.Contains(script, tc.command) {
					t.Fatalf("service control script missing %q: %s", tc.command, script)
				}
				return []byte("ok"), nil
			}))
			response := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(`{"confirm":true,"allow_system_changes":true}`))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(response, req)
			if response.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
			}
			for _, want := range []string{`"core":"` + tc.core + `"`, `"status":"` + tc.status + `"`, tc.command} {
				if !strings.Contains(response.Body.String(), want) {
					t.Fatalf("service control response missing %q: %s", want, response.Body.String())
				}
			}
			if scriptSeen == "" {
				t.Fatalf("runner was not called")
			}
		})
	}
}

func TestCoreServiceControlReturnsSystemdUnavailableError(t *testing.T) {
	router := web.NewRouter(web.WithCoreScriptRunner(func(script string) ([]byte, error) {
		return []byte("systemd is unavailable; cannot restart migate-xray.service"), errors.New("systemd unavailable")
	}))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/xray/restart", strings.NewReader(`{"confirm":true,"allow_system_changes":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", response.Code, response.Body.String())
	}
	for _, want := range []string{`"status":"failed"`, `"error":"restart_failed"`, "systemd is unavailable"} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("systemd unavailable response missing %q: %s", want, response.Body.String())
		}
	}
}

func TestCoreInstallFailureReturnsStructuredActionResult(t *testing.T) {
	var scriptSeen string
	router := web.NewRouter(web.WithCoreScriptRunner(func(script string) ([]byte, error) {
		scriptSeen = script
		return []byte("download Xray release failed"), errors.New("download failed")
	}))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/xray/install", strings.NewReader(`{"confirm":true,"allow_system_changes":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected structured install failure response to be 200, got %d: %s", response.Code, response.Body.String())
	}
	if scriptSeen == "" {
		t.Fatalf("runner was not called")
	}
	for _, want := range []string{`"status":"failed"`, `"error":"install_failed"`, "download Xray release"} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("install failure response missing %q: %s", want, response.Body.String())
		}
	}
}

func TestCoreInstallUnknownCoreReturnsBadRequest(t *testing.T) {
	handler := web.ExposeForTestCoreInstallHandler("bad", func(script string) ([]byte, error) {
		t.Fatalf("runner must not be called for unknown core")
		return nil, nil
	})
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/bad/install", strings.NewReader(`{"confirm":true,"allow_system_changes":true}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", response.Code, response.Body.String())
	}
	assertStandardAPIError(t, response.Body.Bytes(), "unknown_core")
}

func TestCoreInstallScriptsReplaceBinariesAtomically(t *testing.T) {
	script := webAndCoreAdminSource(t)
	for _, want := range []string{
		`systemctl stop migate-xray 2>/dev/null || true`,
		`install_tmp="/usr/local/bin/.xray.new.$$"`,
		`cp "$tmp/xray/xray" "$install_tmp"`,
		`chmod +x "$install_tmp"`,
		`mv -f "$install_tmp" /usr/local/bin/xray`,
		`systemctl stop migate-sing-box 2>/dev/null || true`,
		`systemctl stop migate-sing-box 2>/dev/null || true`,
		`install_tmp="/usr/local/bin/.sing-box.new.$$"`,
		`cp "$tmp"/sing-box-*/sing-box "$install_tmp"`,
		`chmod +x "$install_tmp"`,
		`mv -f "$install_tmp" /usr/local/bin/sing-box`,
		`rm -f "$install_tmp"`,
		`"atomic install /usr/local/bin/xray"`,
		`"atomic install /usr/local/bin/sing-box"`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("WebUI core install script missing atomic replacement contract %q", want)
		}
	}
	for _, forbidden := range []string{
		`cp "$tmp/xray/xray" /usr/local/bin/xray`,
		`cp "$tmp"/sing-box-*/sing-box /usr/local/bin/sing-box`,
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("WebUI core install script must not directly overwrite running binary with %q", forbidden)
		}
	}
}

func TestCoreInstallScriptAvoidsPipefailHead(t *testing.T) {
	script := webAndCoreAdminSource(t)
	for _, want := range []string{
		`/usr/local/bin/xray version | sed -n '1p'`,
		`/usr/local/bin/sing-box version | sed -n '1p'`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("WebUI core install script missing resilient install contract %q", want)
		}
	}
	for _, forbidden := range []string{
		`/usr/local/bin/xray version | head -1`,
		`/usr/local/bin/sing-box version | head -1`,
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("WebUI core install script must avoid pipefail-sensitive version command %q", forbidden)
		}
	}
}

func TestCoreUninstallScriptsRemoveSystemdResidue(t *testing.T) {
	source := webAndCoreAdminSource(t)
	script := sourceBetween(t, source, "func UninstallPlan(core string) (Plan, error)", "func DeletePlan(core string) (Plan, error)")
	for _, want := range []string{
		`systemctl stop migate-xray 2>/dev/null || true`,
		`rm -f /etc/systemd/system/migate-xray.service`,
		`systemctl stop migate-sing-box 2>/dev/null || true`,
		`systemctl reset-failed migate-sing-box 2>/dev/null || true`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("WebUI core uninstall script missing residue cleanup %q", want)
		}
	}
	for _, forbidden := range []string{
		`rm -rf /etc/systemd/system/migate-sing-box.service.d`,
		`rm -f /etc/migate/cores/xray.json /etc/migate/cores/xray.json`,
		`ln -sf /etc/migate/cores/xray.json ` + `/etc/migate/cores/xray.json`,
		`systemctl reset-failed xray 2>/dev/null || true`,
		`systemctl reset-failed sing-box 2>/dev/null || true`,
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("WebUI core uninstall script must not keep legacy cleanup marker %q", forbidden)
		}
	}
	for _, forbidden := range []string{
		`rm -f /usr/local/bin/xray
systemctl daemon-reload`,
		`rm -f /usr/local/bin/sing-box
systemctl daemon-reload`,
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("WebUI core uninstall must keep core binary; delete action owns removal marker %q", forbidden)
		}
	}
	if strings.Contains(script, `rm -rf /etc/systemd/system/migate-sing-box.service.d`) {
		t.Fatalf("WebUI core uninstall script must not remove user-managed migate-sing-box.service drop-ins")
	}
}

func TestCoreDeleteScriptsRemoveCoreBinariesAndKeepConfigs(t *testing.T) {
	source := webAndCoreAdminSource(t)
	script := sourceBetween(t, source, "func DeletePlan(core string) (Plan, error)", "")
	for _, want := range []string{
		`rm -f /usr/local/bin/xray`,
		`rm -f /usr/local/bin/sing-box`,
		`Xray core binary removed. Configuration was kept.`,
		`sing-box core binary removed. Configuration was kept.`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("WebUI core delete script missing %q", want)
		}
	}
	for _, forbidden := range []string{
		`rm -f /etc/migate/cores/xray.json`,
		`rm -f /etc/migate/cores/sing-box.json`,
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("WebUI core delete must keep config file marker %q", forbidden)
		}
	}
}

func TestCoreInstallScriptsSeedConfigsMatchingGeneratedDefaults(t *testing.T) {
	script := webAndCoreAdminSource(t)
	for _, want := range []string{
		`"tag": "xray-out-1"`,
		`"tag": "xray-out-2"`,
		`"tag": "xray-out-3"`,
		`"tag": "api"`,
		`"StatsService"`,
		`"tag": "singbox-out-1"`,
		`"tag": "singbox-out-2"`,
		`write_migate_default_xray_config()`,
		`write_migate_default_singbox_config()`,
		`atomic_write_file()`,
		`backup_migate_invalid_core_config()`,
		`existing Xray config check failed; backing it up and writing MiGate default config`,
		`backup_migate_invalid_core_config /etc/migate/cores/xray.json`,
		`existing sing-box config check failed; backing it up and writing MiGate default config`,
		`backup_migate_invalid_core_config /etc/migate/cores/sing-box.json`,
		`/var/lib/migate/backups/xray-config-invalid-$(date +%Y%m%d-%H%M%S).json`,
		`/var/lib/migate/backups/sing-box-config-invalid-$(date +%Y%m%d-%H%M%S).json`,
		`chmod 0640 /etc/migate/cores/xray.json`,
		`chmod 0640 /etc/migate/cores/sing-box.json`,
		`/usr/local/bin/xray run -test -c "$tmp_config"`,
		`/usr/local/bin/sing-box check -c "$tmp_config"`,
		`mv -f "$tmp_config" /etc/migate/cores/xray.json`,
		`mv -f "$tmp_config" /etc/migate/cores/sing-box.json`,
		`/usr/local/bin/xray run -test -c /etc/migate/cores/xray.json`,
		`/usr/local/bin/sing-box check -c /etc/migate/cores/sing-box.json`,
		`systemctl stop migate-sing-box 2>/dev/null || true`,
		`systemctl reset-failed migate-sing-box 2>/dev/null || true`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("WebUI core install script default config contract missing %q", want)
		}
	}
	for _, forbidden := range []string{
		`"tag":"direct"`,
		`"tag":"blocked"`,
		`"outbounds":[{"type":"direct","tag":"direct"}]`,
		strings.Join([]string{`mv -f /etc/migate/cores/xray.json "/etc/migate/cores/xray.json.migate`, `-backup.`}, ""),
		strings.Join([]string{`.migate`, `-backup.$(date +%Y%m%d%H%M%S)`}, ""),
		`ln -sf /etc/migate/cores/xray.json ` + `/etc/migate/cores/xray.json`,
		`systemctl is-active --quiet xray`,
		`systemctl is-active --quiet sing-box`,
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("WebUI core install script must not seed legacy default core config marker %q", forbidden)
		}
	}
}

func TestCoreInstallScriptsBackupInvalidConfigsBeforeRestart(t *testing.T) {
	xrayScript := webCoreInstallScript(t, "xray")
	for _, want := range []string{
		`if ! /usr/local/bin/xray run -test -c /etc/migate/cores/xray.json; then`,
		`backup_migate_invalid_core_config /etc/migate/cores/xray.json`,
		`/usr/local/bin/xray run -test -c /etc/migate/cores/xray.json`,
		`systemctl restart migate-xray`,
	} {
		if !strings.Contains(xrayScript, want) {
			t.Fatalf("Xray install script missing invalid-config repair step %q", want)
		}
	}
	repairIdx := strings.Index(xrayScript, `backup_migate_invalid_core_config /etc/migate/cores/xray.json`)
	restartIdx := strings.LastIndex(xrayScript, "systemctl restart migate-xray\n")
	if repairIdx < 0 || restartIdx < 0 || repairIdx > restartIdx {
		t.Fatalf("Xray install script must repair invalid config before service restart")
	}

	singboxScript := webCoreInstallScript(t, "singbox")
	for _, want := range []string{
		`if ! /usr/local/bin/sing-box check -c /etc/migate/cores/sing-box.json; then`,
		`backup_migate_invalid_core_config /etc/migate/cores/sing-box.json`,
		`/usr/local/bin/sing-box check -c /etc/migate/cores/sing-box.json`,
		`systemctl restart migate-sing-box`,
	} {
		if !strings.Contains(singboxScript, want) {
			t.Fatalf("sing-box install script missing invalid-config repair step %q", want)
		}
	}
	repairIdx = strings.Index(singboxScript, `backup_migate_invalid_core_config /etc/migate/cores/sing-box.json`)
	restartIdx = strings.LastIndex(singboxScript, "systemctl restart migate-sing-box\n")
	if repairIdx < 0 || restartIdx < 0 || repairIdx > restartIdx {
		t.Fatalf("sing-box install script must repair invalid config before service restart")
	}
}

func TestCoreXrayInstallScriptUsesStandardConfigPathOnly(t *testing.T) {
	script := webCoreInstallScript(t, "xray")
	for _, want := range []string{
		`if [ ! -f /etc/migate/cores/xray.json ]; then`,
		`/usr/local/bin/xray run -test -c /etc/migate/cores/xray.json`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("Xray install script must use standard config path, missing %q", want)
		}
	}
	for _, forbidden := range []string{
		`ln -sf /etc/migate/cores/xray.json ` + `/etc/migate/cores/xray.json`,
		`/etc/migate/cores/xray.json exists and is not a symlink`,
		`Move it aside or replace it with a symlink`,
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("Xray install script must not retain compat config behavior %q", forbidden)
		}
	}
}

func TestCoreXrayInstallScriptVerifiesChecksumBeforeExtracting(t *testing.T) {
	script := webCoreInstallScript(t, "xray")
	for _, want := range []string{
		`url="https://github.com/XTLS/Xray-core/releases/download/v${version}/${asset_name}"`,
		`dgst_url="${url}.dgst"`,
		`curl -fL "$url" -o "$tmp/$asset_name"`,
		`curl -fL "$dgst_url" -o "$tmp/$asset_name.dgst"`,
		`awk -F'= ' '/^SHA2-256=/{print $2}' "$tmp/$asset_name.dgst" | grep -E '^[0-9a-fA-F]{64}$' > "$tmp/$asset_name.digest"`,
		`wc -l < "$tmp/$asset_name.digest"`,
		`printf '%s  %s\n' "$digest" "$asset_name" > "$tmp/$asset_name.sha256"`,
		`sha256sum -c "$asset_name.sha256"`,
		`unzip -oq "$tmp/$asset_name" -d "$tmp/xray"`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("Xray WebUI install script missing checksum contract %q", want)
		}
	}
	if strings.Index(script, `sha256sum -c "$asset_name.sha256"`) > strings.Index(script, `unzip -oq "$tmp/$asset_name" -d "$tmp/xray"`) {
		t.Fatalf("Xray WebUI install script must verify checksum before extracting archive")
	}
}

func TestCoreSingboxInstallScriptVerifiesChecksumBeforeExtracting(t *testing.T) {
	script := webCoreInstallScript(t, "singbox")
	for _, want := range []string{
		`url="https://github.com/SagerNet/sing-box/releases/download/v${version}/${asset_name}"`,
		`release_api_url="https://api.github.com/repos/SagerNet/sing-box/releases/tags/v${version}"`,
		`curl -fL "$url" -o "$tmp/$asset_name"`,
		`curl -fsSL "$release_api_url" -o "$tmp/release.json"`,
		`/"name": "/ { in_asset=0 }`,
		`printf '%s  %s\n' "$digest" "$asset_name" > "$tmp/sing-box.tar.gz.sha256"`,
		`sha256sum -c "sing-box.tar.gz.sha256"`,
		`tar --no-same-owner -xzf "$tmp/$asset_name" -C "$tmp"`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("sing-box WebUI install script missing checksum contract %q", want)
		}
	}
	if strings.Index(script, `sha256sum -c "sing-box.tar.gz.sha256"`) > strings.Index(script, `tar --no-same-owner -xzf "$tmp/$asset_name"`) {
		t.Fatalf("sing-box WebUI install script must verify checksum before extracting archive")
	}
}

func TestCoreSingboxInstallCommandsIncludeChecksumVerification(t *testing.T) {
	script := webCoreInstallScript(t, "singbox")
	for _, want := range []string{
		`download sing-box release`,
		`verify sing-box release checksum`,
		`atomic install /usr/local/bin/sing-box`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("sing-box WebUI command list missing %q", want)
		}
	}
}

func TestCoreInstallersDoNotExecuteUnverifiedRemoteScripts(t *testing.T) {
	webSource := webPackageSource(t)
	coreadminSource := goPackageSource(t, "../service/coreadmin")
	certSource := goPackageSource(t, "../service/cert")
	source := webSource + "\n" + coreadminSource + "\n" + certSource
	for _, forbidden := range []string{
		"get.acme.sh",
		"Xray-install/raw/main/install-release.sh",
		`bash "$tmp/install-release.sh"`,
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("MiGate must not download and execute unverified remote installer %q", forbidden)
		}
	}
	for _, want := range []string{
		"golang.org/x/crypto/acme",
		"download Xray release",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("source missing safe installer marker %q", want)
		}
	}
}
