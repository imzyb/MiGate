package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	panelcfg "github.com/imzyb/MiGate/internal/config"
	"github.com/imzyb/MiGate/internal/paths"
	"github.com/imzyb/MiGate/internal/web"
	"github.com/imzyb/MiGate/internal/xray"
)

func loginForTest(t *testing.T, router http.Handler) *http.Cookie {
	t.Helper()
	loginResp := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(`{"username":"admin","password":"secret"}`)))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("Origin", "http://127.0.0.1")
	loginReq.Host = "127.0.0.1"
	loginReq.RemoteAddr = "127.0.0.1:12345"
	router.ServeHTTP(loginResp, loginReq)
	if loginResp.Code != http.StatusOK {
		t.Fatalf("expected login 200, got %d: %s", loginResp.Code, loginResp.Body.String())
	}
	for _, c := range loginResp.Result().Cookies() {
		if c.Name == "migate_session" {
			return c
		}
	}
	t.Fatal("login should set session cookie")
	return nil
}

func useTempRuntimePaths(t *testing.T, root string) {
	t.Helper()
	origCoreConfigDir := paths.CoreConfigDir
	origXrayConfig := paths.XrayConfig
	origSingboxConfig := paths.SingboxConfig
	origConfigDir := paths.ConfigDir
	origDatabase := paths.Database
	origRunDir := paths.RunDir
	origApplyLock := paths.ApplyLock
	origInstallLock := paths.InstallLock
	origSyncLock := paths.SyncLock
	origUpgradeLock := paths.UpgradeLock
	paths.ConfigDir = filepath.Join(root, "etc", "migate")
	paths.CoreConfigDir = filepath.Join(paths.ConfigDir, "cores")
	paths.XrayConfig = filepath.Join(paths.CoreConfigDir, "xray.json")
	paths.SingboxConfig = filepath.Join(paths.CoreConfigDir, "sing-box.json")
	paths.Database = filepath.Join(root, "var", "lib", "migate", "migate.db")
	paths.RunDir = filepath.Join(root, "run", "migate")
	paths.ApplyLock = filepath.Join(paths.RunDir, "apply.lock")
	paths.InstallLock = filepath.Join(paths.RunDir, "install.lock")
	paths.SyncLock = filepath.Join(paths.RunDir, "sync.lock")
	paths.UpgradeLock = filepath.Join(paths.RunDir, "upgrade.lock")
	t.Cleanup(func() {
		paths.CoreConfigDir = origCoreConfigDir
		paths.XrayConfig = origXrayConfig
		paths.SingboxConfig = origSingboxConfig
		paths.ConfigDir = origConfigDir
		paths.Database = origDatabase
		paths.RunDir = origRunDir
		paths.ApplyLock = origApplyLock
		paths.InstallLock = origInstallLock
		paths.SyncLock = origSyncLock
		paths.UpgradeLock = origUpgradeLock
	})
}

func TestRouterFromPanelConfigOpensConfiguredDatabaseStore(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "panel.json")
	databasePath := filepath.Join(tmp, "migate.db")
	config := `{"panel_port":9999,"panel_username":"admin","panel_password":"secret","web_base_path":"/","database_path":"` + databasePath + `"}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	router, cleanup, err := routerFromConfig(configPath)
	if err != nil {
		t.Fatalf("router from config: %v", err)
	}
	defer cleanup()

	loginResp := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(`{"username":"admin","password":"secret"}`)))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("Origin", "http://127.0.0.1")
	loginReq.Host = "127.0.0.1"
	loginReq.RemoteAddr = "127.0.0.1:12345"
	router.ServeHTTP(loginResp, loginReq)
	if loginResp.Code != http.StatusOK {
		t.Fatalf("expected login 200, got %d: %s", loginResp.Code, loginResp.Body.String())
	}
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

	payload := []byte(`{"remark":"真机入口","protocol":"vless","port":8443,"network":"tcp","security":"reality"}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/inbounds", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://127.0.0.1")
	req.Host = "127.0.0.1"
	req.RemoteAddr = "127.0.0.1:12345"
	req.AddCookie(sessionCookie)
	router.ServeHTTP(response, req)

	if response.Code != http.StatusCreated {
		t.Fatalf("expected configured store to create inbound, got %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"remark":"真机入口"`) {
		t.Fatalf("create response missing inbound: %s", response.Body.String())
	}
}

func TestRouterFromPanelConfigUsesStandardXrayConfigPath(t *testing.T) {
	tmp := t.TempDir()
	useTempRuntimePaths(t, tmp)
	configPath := filepath.Join(tmp, "panel.json")
	databasePath := filepath.Join(tmp, "migate.db")
	config := `{"panel_port":9999,"panel_username":"admin","panel_password":"secret","database_path":"` + databasePath + `"}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	router, cleanup, err := routerFromConfig(configPath)
	if err != nil {
		t.Fatalf("router from config: %v", err)
	}
	defer cleanup()

	loginResp := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(`{"username":"admin","password":"secret"}`)))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("Origin", "http://127.0.0.1")
	loginReq.Host = "127.0.0.1"
	loginReq.RemoteAddr = "127.0.0.1:12345"
	router.ServeHTTP(loginResp, loginReq)
	if loginResp.Code != http.StatusOK {
		t.Fatalf("expected login 200, got %d: %s", loginResp.Code, loginResp.Body.String())
	}
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

	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/xray/config/preview", nil)
	req.AddCookie(sessionCookie)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected preview 200, got %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"config_path":"`+paths.XrayConfig+`"`) {
		t.Fatalf("preview should use standard runtime xray config path, got %s", response.Body.String())
	}
}

func TestRouterFromPanelConfigIgnoresUnknownConfigFields(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "panel.json")
	databasePath := filepath.Join(tmp, "migate.db")
	config := `{"panel_port":9999,"panel_username":"admin","panel_password":"secret","web_base_path":"/","database_path":"` + databasePath + `","legacy_field":"kept-by-old-install"}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	router, cleanup, err := routerFromConfig(configPath)
	if err != nil {
		t.Fatalf("router from config with unknown fields: %v", err)
	}
	defer cleanup()

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected health 200, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestRouterFromPanelConfigXrayApplyPreservesCommandStderr(t *testing.T) {
	tmp := t.TempDir()
	useTempRuntimePaths(t, tmp)
	configPath := filepath.Join(tmp, "panel.json")
	databasePath := filepath.Join(tmp, "migate.db")
	config := `{"panel_port":9999,"panel_username":"admin","panel_password":"secret","database_path":"` + databasePath + `"}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "xray"), []byte("#!/bin/sh\nif [ \"$1\" = \"run\" ]; then printf 'xray stderr detail\\n' >&2; exit 1; fi\nprintf 'Xray 26.3.27\\n'\n"), 0o755); err != nil {
		t.Fatalf("write fake xray: %v", err)
	}
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath)

	router, cleanup, err := routerFromConfig(configPath)
	if err != nil {
		t.Fatalf("router from config: %v", err)
	}
	defer cleanup()
	sessionCookie := loginForTest(t, router)

	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/xray/apply", bytes.NewReader([]byte(`{"confirm":true,"allow_system_changes":true}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://127.0.0.1")
	req.Host = "127.0.0.1"
	req.RemoteAddr = "127.0.0.1:12345"
	req.AddCookie(sessionCookie)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected structured apply response 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"error":"validation_failed"`, "xray stderr detail", `"error_output":"xray stderr detail`} {
		if !strings.Contains(body, want) {
			t.Fatalf("xray apply response should preserve stderr %q, got %s", want, body)
		}
	}
}

func TestRouterFromPanelConfigEnablesAuthWhenCredentialsPresent(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "panel.json")
	config := `{"panel_port":9999,"panel_username":"admin","panel_password":"secret","database_path":"` + filepath.Join(tmp, "migate.db") + `"}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	router, cleanup, err := routerFromConfig(configPath)
	if err != nil {
		t.Fatalf("router from config: %v", err)
	}
	defer cleanup()

	// Without cookie -> SPA shell; the React app performs session routing.
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 SPA shell without auth, got %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), `id="root"`) {
		t.Fatalf("expected SPA shell without auth, got: %s", response.Body.String())
	}
	unauthAPI := httptest.NewRecorder()
	router.ServeHTTP(unauthAPI, httptest.NewRequest(http.MethodGet, "/api/inbounds", nil))
	if unauthAPI.Code != http.StatusUnauthorized {
		t.Fatalf("expected protected API 401 without auth, got %d", unauthAPI.Code)
	}

	// Login -> 200 with cookie
	loginResp := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(`{"username":"admin","password":"secret"}`)))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("Origin", "http://127.0.0.1")
	loginReq.Host = "127.0.0.1"
	loginReq.RemoteAddr = "127.0.0.1:12345"
	router.ServeHTTP(loginResp, loginReq)
	if loginResp.Code != http.StatusOK {
		t.Fatalf("expected 200 login, got %d", loginResp.Code)
	}

	cookies := loginResp.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "migate_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session cookie after login")
	}

	// With cookie -> 200
	authResp := httptest.NewRecorder()
	authReq := httptest.NewRequest(http.MethodGet, "/", nil)
	authReq.AddCookie(sessionCookie)
	router.ServeHTTP(authResp, authReq)
	if authResp.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid cookie, got %d", authResp.Code)
	}
}

func TestRouterFromPanelConfigMountsConfiguredWebBasePath(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "panel_base_path.json")
	config := `{"panel_port":9999,"panel_username":"admin","panel_password":"secret","web_base_path":"/migate","database_path":"` + filepath.Join(tmp, "migate.db") + `"}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	router, cleanup, err := routerFromConfig(configPath)
	if err != nil {
		t.Fatalf("router from config: %v", err)
	}
	defer cleanup()

	for _, tc := range []struct {
		path string
		want int
	}{
		{path: "/migate/login", want: http.StatusOK},
		{path: "/migate/api/health", want: http.StatusOK},
		{path: "/migate", want: http.StatusPermanentRedirect},
		{path: "/migate/", want: http.StatusOK},
	} {
		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		router.ServeHTTP(resp, req)
		if resp.Code != tc.want {
			t.Fatalf("%s: expected %d, got %d: %s", tc.path, tc.want, resp.Code, resp.Body.String())
		}
		if tc.path == "/migate/" {
			if !strings.Contains(resp.Body.String(), `id="root"`) {
				t.Fatalf("%s: expected SPA shell for unauthenticated panel root, got: %s", tc.path, resp.Body.String())
			}
		}
	}
}

func TestRouterFromPanelConfigCanTrustProxyHeaders(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "panel_trust_proxy.json")
	config := `{"panel_port":9999,"panel_username":"admin","panel_password":"secret","trust_proxy":true,"database_path":"` + filepath.Join(tmp, "migate.db") + `"}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	router, cleanup, err := routerFromConfig(configPath)
	if err != nil {
		t.Fatalf("router from config: %v", err)
	}
	defer cleanup()

	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(`{"username":"admin","password":"secret"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 login, got %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("trusted proxy HTTPS response should set HSTS")
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == "migate_session" && cookie.Secure {
			return
		}
	}
	t.Fatalf("trusted proxy HTTPS login should set Secure session cookie: %+v", response.Result().Cookies())
}

func TestRouterFromPanelConfigWithoutDatabaseKeepsPanelOptions(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "panel_no_db.json")
	config := `{"panel_port":9999,"panel_username":"admin","panel_password":"secret","web_base_path":"/panel","trust_proxy":true}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	router, cleanup, err := routerFromConfig(configPath)
	if err != nil {
		t.Fatalf("router from config: %v", err)
	}
	defer cleanup()

	wrongBase := httptest.NewRecorder()
	router.ServeHTTP(wrongBase, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if wrongBase.Code != http.StatusNotFound {
		t.Fatalf("expected base path to apply without database, got %d", wrongBase.Code)
	}

	loginResp := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/panel/api/login", bytes.NewReader([]byte(`{"username":"admin","password":"secret"}`)))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("Origin", "https://example.com")
	loginReq.Header.Set("X-Forwarded-Proto", "https")
	router.ServeHTTP(loginResp, loginReq)
	if loginResp.Code != http.StatusOK {
		t.Fatalf("expected login 200, got %d: %s", loginResp.Code, loginResp.Body.String())
	}
	if loginResp.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("trust_proxy should apply without database")
	}
	for _, cookie := range loginResp.Result().Cookies() {
		if cookie.Name == "migate_session" && cookie.Path == "/panel" && cookie.Secure {
			return
		}
	}
	t.Fatalf("expected secure /panel session cookie without database: %+v", loginResp.Result().Cookies())
}

func TestRouterFromPanelConfigRejectsMissingCredentials(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "panel_noauth.json")
	config := `{"panel_port":9999,"database_path":"` + filepath.Join(tmp, "migate.db") + `"}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, cleanup, err := routerFromConfig(configPath)
	if cleanup != nil {
		defer cleanup()
	}
	if err == nil || !strings.Contains(err.Error(), "panel_username and panel_password are required") {
		t.Fatalf("expected missing credentials error, got %v", err)
	}
}

func TestCLIPrintsInteractiveMenuForBareCommand(t *testing.T) {
	var out bytes.Buffer
	exitCode := runCLI([]string{}, &out, &bytes.Buffer{}, &fakeRunner{})
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	menu := out.String()
	for _, want := range []string{
		"MiGate CLI",
		"用法:",
		"mg status",
		"mg logs",
		"mg restart",
		"mg url",
		"mg update",
		"mg version",
		"mg uninstall",
		"服务模式:",
		"migate serve --config /etc/migate/panel.json",
	} {
		if !strings.Contains(menu, want) {
			t.Fatalf("CLI menu missing %q:\n%s", want, menu)
		}
	}
}

func TestRunServerRejectsMissingConfig(t *testing.T) {
	var stderr bytes.Buffer
	oldStderr := os.Stderr
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = writePipe
	defer func() { os.Stderr = oldStderr }()

	exitCode := runServer(nil)
	_ = writePipe.Close()
	_, _ = stderr.ReadFrom(readPipe)

	if exitCode != 1 {
		t.Fatalf("expected exit 1 without config, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "serve mode requires --config") {
		t.Fatalf("expected missing config error, got %q", stderr.String())
	}
}

func TestServeDefaultBindHostIsLoopback(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	if !strings.Contains(string(source), `fs.StringVar(&host, "host", "127.0.0.1", "bind host")`) {
		t.Fatalf("serve --host default must remain loopback")
	}
}

func TestCLIStatusUsesSystemctlWithoutStartingServer(t *testing.T) {
	runner := &fakeRunner{outputs: map[string]string{
		"systemctl show migate-sing-box --property=LoadState --value": "loaded\n",
		"systemctl is-active migate":                                  "active\n",
		"systemctl is-active migate-xray":                             "inactive\n",
		"systemctl is-active migate-sing-box":                         "inactive\n",
	}}
	var out bytes.Buffer
	exitCode := runCLI([]string{"status"}, &out, &bytes.Buffer{}, runner)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	if !strings.Contains(out.String(), "MiGate 面板: 运行中") || !strings.Contains(out.String(), "Xray: 已停止") || !strings.Contains(out.String(), "sing-box: 已停止") {
		t.Fatalf("unexpected status output: %s", out.String())
	}
	want := []string{
		"systemctl is-active migate",
		"systemctl is-active migate-xray",
		"systemctl is-active migate-sing-box",
	}
	if strings.Join(runner.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("unexpected status calls: %+v", runner.calls)
	}
}

func TestCLIStatusDoesNotFallbackToLegacySingboxService(t *testing.T) {
	runner := &fakeRunner{outputs: map[string]string{
		"systemctl show migate-sing-box --property=LoadState --value": "not-found\n",
		"systemctl is-active migate":                                  "active\n",
		"systemctl is-active migate-xray":                             "inactive\n",
		"systemctl is-active migate-sing-box":                         "inactive\n",
	}}
	var out bytes.Buffer
	exitCode := runCLI([]string{"status"}, &out, &bytes.Buffer{}, runner)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	want := []string{
		"systemctl is-active migate",
		"systemctl is-active migate-xray",
		"systemctl is-active migate-sing-box",
	}
	if strings.Join(runner.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("unexpected calls: %+v", runner.calls)
	}
}

func TestCLIStatusReportsXrayNotFoundAsStopped(t *testing.T) {
	runner := &fakeRunner{outputs: map[string]string{
		"systemctl show migate-sing-box --property=LoadState --value": "loaded\n",
		"systemctl is-active migate":                                  "active\n",
		"systemctl is-active migate-xray":                             "unknown\n",
		"systemctl is-active migate-sing-box":                         "active\n",
	}}
	var out bytes.Buffer
	exitCode := runCLI([]string{"status"}, &out, &bytes.Buffer{}, runner)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	if !strings.Contains(out.String(), "Xray: 已停止") {
		t.Fatalf("status should include stopped Xray when unit is not active: %s", out.String())
	}
}

func TestCLIVersionPrintsCurrentVersion(t *testing.T) {
	old := Version
	Version = "v9.9.9"
	defer func() { Version = old }()
	var out bytes.Buffer
	exitCode := runCLI([]string{"version"}, &out, &bytes.Buffer{}, &fakeRunner{})
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	if got := out.String(); !strings.Contains(got, "MiGate version: v9.9.9") {
		t.Fatalf("unexpected version output: %q", got)
	}
}

func TestCLIUpdateDelegatesToInstallerUpdateMode(t *testing.T) {
	runner := &fakeRunner{outputs: map[string]string{
		"/usr/local/bin/migate-install --update": "MiGate updated\n",
	}}
	var out bytes.Buffer
	exitCode := runCLI([]string{"update"}, &out, &bytes.Buffer{}, runner)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	if got := out.String(); !strings.Contains(got, "MiGate updated") {
		t.Fatalf("expected update output, got %q", got)
	}
	if len(runner.calls) != 1 || runner.calls[0] != "/usr/local/bin/migate-install --update" {
		t.Fatalf("unexpected update calls: %+v", runner.calls)
	}
}

func TestCLIUpdateForwardsOptionalVersion(t *testing.T) {
	runner := &fakeRunner{outputs: map[string]string{
		"/usr/local/bin/migate-install --update --version v1.0.6": "MiGate updated to v1.0.6\n",
	}}
	var out bytes.Buffer
	exitCode := runCLI([]string{"update", "v1.0.6"}, &out, &bytes.Buffer{}, runner)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	if got := out.String(); !strings.Contains(got, "v1.0.6") {
		t.Fatalf("expected versioned update output, got %q", got)
	}
	if len(runner.calls) != 1 || runner.calls[0] != "/usr/local/bin/migate-install --update --version v1.0.6" {
		t.Fatalf("unexpected update calls: %+v", runner.calls)
	}
}

func TestCLIUpdateReportsInstallerFailure(t *testing.T) {
	runner := &fakeRunner{
		outputs: map[string]string{"/usr/local/bin/migate-install --update": "download failed\n"},
		errors:  map[string]error{"/usr/local/bin/migate-install --update": errors.New("exit status 1")},
	}
	var out, stderr bytes.Buffer
	exitCode := runCLI([]string{"update"}, &out, &stderr, runner)
	if exitCode != 1 {
		t.Fatalf("expected exit 1, got %d", exitCode)
	}
	if !strings.Contains(out.String(), "download failed") || !strings.Contains(stderr.String(), "update failed") {
		t.Fatalf("expected failure output, stdout=%q stderr=%q", out.String(), stderr.String())
	}
}

func TestCLIEnglishLanguageFlagSwitchesOutput(t *testing.T) {
	runner := &fakeRunner{outputs: map[string]string{
		"systemctl show migate-sing-box --property=LoadState --value": "loaded\n",
		"systemctl is-active migate":                                  "active\n",
		"systemctl is-active migate-xray":                             "inactive\n",
		"systemctl is-active migate-sing-box":                         "inactive\n",
	}}
	var out bytes.Buffer
	exitCode := runCLI([]string{"--lang", "en", "status"}, &out, &bytes.Buffer{}, runner)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	if !strings.Contains(out.String(), "MiGate Panel: running") || !strings.Contains(out.String(), "Xray: stopped") || !strings.Contains(out.String(), "sing-box: stopped") {
		t.Fatalf("expected English status output, got: %s", out.String())
	}
}

func TestCLIEnglishLanguageEnvironmentSwitchesOutput(t *testing.T) {
	t.Setenv("MIGATE_LANG", "en")
	var out bytes.Buffer
	exitCode := runCLI([]string{}, &out, &bytes.Buffer{}, &fakeRunner{})
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	if !strings.Contains(out.String(), "Usage:") || !strings.Contains(out.String(), "Common commands:") {
		t.Fatalf("expected English menu from MIGATE_LANG=en, got:\n%s", out.String())
	}
}

func TestCLIRejectsUnsupportedLanguage(t *testing.T) {
	var stderr bytes.Buffer
	exitCode := runCLI([]string{"--lang", "ja", "status"}, &bytes.Buffer{}, &stderr, &fakeRunner{})
	if exitCode != 2 {
		t.Fatalf("expected exit 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "unsupported language") || !strings.Contains(stderr.String(), "zh, en") {
		t.Fatalf("unexpected unsupported language error: %q", stderr.String())
	}
}

func TestCLIOperationsMenuListsExpandedCommands(t *testing.T) {
	var out bytes.Buffer
	exitCode := runCLI([]string{}, &out, &bytes.Buffer{}, &fakeRunner{})
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	menu := out.String()
	for _, want := range []string{"mg doctor", "mg info", "mg reset-password", "mg url --public", "mg update --check", "mg logs -f", "mg restart all", "mg backup", "mg restore", "mg ports"} {
		if !strings.Contains(menu, want) {
			t.Fatalf("expanded CLI menu missing %q:\n%s", want, menu)
		}
	}
}

func TestCLIDoctorPrintsPanelRuntimeAndResourceChecks(t *testing.T) {
	tmp := t.TempDir()
	oldPath := defaultPanelConfigPath
	oldXrayConfig := paths.XrayConfig
	oldSingboxConfig := paths.SingboxConfig
	oldBackupDir := paths.BackupDir
	oldLogDir := paths.LogDir
	oldRunDir := paths.RunDir
	oldXrayBinary := paths.XrayBinary
	oldSingboxBinary := paths.SingboxBinary
	defaultPanelConfigPath = filepath.Join(tmp, "panel.json")
	paths.XrayConfig = filepath.Join(tmp, "cores", "xray.json")
	paths.SingboxConfig = filepath.Join(tmp, "cores", "sing-box.json")
	paths.BackupDir = filepath.Join(tmp, "backups")
	paths.LogDir = filepath.Join(tmp, "logs")
	paths.RunDir = filepath.Join(tmp, "run")
	paths.XrayBinary = filepath.Join(tmp, "bin", "xray")
	paths.SingboxBinary = filepath.Join(tmp, "bin", "sing-box")
	defer func() {
		defaultPanelConfigPath = oldPath
		paths.XrayConfig = oldXrayConfig
		paths.SingboxConfig = oldSingboxConfig
		paths.BackupDir = oldBackupDir
		paths.LogDir = oldLogDir
		paths.RunDir = oldRunDir
		paths.XrayBinary = oldXrayBinary
		paths.SingboxBinary = oldSingboxBinary
	}()
	dbPath := filepath.Join(tmp, "migate.db")
	config := `{"panel_port":9999,"web_base_path":"/migate","database_path":"` + dbPath + `"}`
	if err := os.WriteFile(defaultPanelConfigPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	database, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if _, err := database.Exec(`CREATE TABLE smoke (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("create db table: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	for _, path := range []string{paths.XrayConfig, paths.SingboxConfig} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir core config: %v", err)
		}
		if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
			t.Fatalf("write core config: %v", err)
		}
	}
	for _, dir := range []string{paths.BackupDir, paths.LogDir, paths.RunDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	for _, path := range []string{paths.XrayBinary, paths.SingboxBinary} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir binary dir: %v", err)
		}
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("write binary marker: %v", err)
		}
	}
	runner := &fakeRunner{outputs: map[string]string{
		"systemctl show migate-sing-box --property=LoadState --value": "loaded\n",
		"systemctl is-active migate":                                  "active\n",
		"systemctl is-active migate-xray":                             "active\n",
		"systemctl is-active migate-sing-box":                         "active\n",
		"ss -ltn":                                                     "LISTEN 0 4096 *:9999 *:*\n",
		"free -m":                                                     "Mem: 900 400 500\nSwap: 512 0 512\n",
		"df -h /":                                                     "/dev/sda1 50G 10G 40G 20% /\n",
	}}
	var out bytes.Buffer
	exitCode := runCLI([]string{"doctor"}, &out, &bytes.Buffer{}, runner)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	body := out.String()
	for _, want := range []string{"MiGate 诊断", "MiGate 面板: 运行中", "WebUI: http://SERVER_IP:9999/migate", "Xray: 已安装", "sing-box: 已安装", "配置文件: 正常", "数据库: 正常", "核心配置", "目录", "内存", "磁盘"} {
		if !strings.Contains(body, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, body)
		}
	}
}

func TestCLIDoctorReturnsFailureForCriticalMissingRuntimeState(t *testing.T) {
	tmp := t.TempDir()
	oldPath := defaultPanelConfigPath
	oldXrayConfig := paths.XrayConfig
	oldSingboxConfig := paths.SingboxConfig
	oldBackupDir := paths.BackupDir
	oldLogDir := paths.LogDir
	oldRunDir := paths.RunDir
	oldXrayBinary := paths.XrayBinary
	oldSingboxBinary := paths.SingboxBinary
	defaultPanelConfigPath = filepath.Join(tmp, "panel.json")
	paths.XrayConfig = filepath.Join(tmp, "cores", "xray.json")
	paths.SingboxConfig = filepath.Join(tmp, "cores", "sing-box.json")
	paths.BackupDir = filepath.Join(tmp, "backups")
	paths.LogDir = filepath.Join(tmp, "logs")
	paths.RunDir = filepath.Join(tmp, "run")
	paths.XrayBinary = filepath.Join(tmp, "bin", "xray")
	paths.SingboxBinary = filepath.Join(tmp, "bin", "sing-box")
	defer func() {
		defaultPanelConfigPath = oldPath
		paths.XrayConfig = oldXrayConfig
		paths.SingboxConfig = oldSingboxConfig
		paths.BackupDir = oldBackupDir
		paths.LogDir = oldLogDir
		paths.RunDir = oldRunDir
		paths.XrayBinary = oldXrayBinary
		paths.SingboxBinary = oldSingboxBinary
	}()
	if err := os.WriteFile(defaultPanelConfigPath, []byte(`{"panel_port":9999,"database_path":"`+filepath.Join(tmp, "missing.db")+`"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	runner := &fakeRunner{outputs: map[string]string{
		"systemctl is-active migate":          "active\n",
		"systemctl is-active migate-xray":     "inactive\n",
		"systemctl is-active migate-sing-box": "active\n",
		"free -m":                             "Mem: 900 400 500\n",
		"df -h /":                             "/dev/sda1 50G 10G 40G 20% /\n",
	}}
	var out bytes.Buffer
	if code := runCLI([]string{"doctor"}, &out, &bytes.Buffer{}, runner); code != 1 {
		t.Fatalf("doctor should fail for missing critical runtime state, got %d\n%s", code, out.String())
	}
	body := out.String()
	for _, want := range []string{"Xray: 已停止", "数据库: 缺失", "Xray: 未安装", "核心配置", "目录"} {
		if !strings.Contains(body, want) {
			t.Fatalf("doctor failure output missing %q:\n%s", want, body)
		}
	}
}

func TestSQLiteReadOnlyDSNUsesURIWithEscapedPath(t *testing.T) {
	got := sqliteReadOnlyDSN("/tmp/migate data/migate.db")
	if got != "file:///tmp/migate%20data/migate.db?mode=ro" {
		t.Fatalf("unexpected sqlite readonly dsn: %s", got)
	}
}

func TestCLIInfoShowsPanelDetailsWithoutPassword(t *testing.T) {
	tmp := t.TempDir()
	oldPath := defaultPanelConfigPath
	defaultPanelConfigPath = filepath.Join(tmp, "panel.json")
	defer func() { defaultPanelConfigPath = oldPath }()
	config := `{"panel_port":9999,"panel_username":"admin","panel_password":"secret","web_base_path":"/migate","database_path":"/var/lib/migate/migate.db"}`
	if err := os.WriteFile(defaultPanelConfigPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	old := Version
	Version = "v1.2.3"
	defer func() { Version = old }()
	var out bytes.Buffer
	exitCode := runCLI([]string{"info"}, &out, &bytes.Buffer{}, &fakeRunner{})
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	body := out.String()
	for _, want := range []string{"MiGate 信息", "版本: v1.2.3", "WebUI: http://SERVER_IP:9999/migate", "用户名: admin", "配置文件: " + defaultPanelConfigPath, "数据库: /var/lib/migate/migate.db", "mg reset-password"} {
		if !strings.Contains(body, want) {
			t.Fatalf("info output missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "secret") {
		t.Fatalf("info leaked password: %s", body)
	}
}

func TestCLIResetPasswordUpdatesConfigAndRestartsService(t *testing.T) {
	tmp := t.TempDir()
	oldPath := defaultPanelConfigPath
	defaultPanelConfigPath = filepath.Join(tmp, "panel.json")
	defer func() { defaultPanelConfigPath = oldPath }()
	config := `{"panel_port":9999,"panel_username":"admin","panel_password":"old","web_base_path":"/migate"}`
	if err := os.WriteFile(defaultPanelConfigPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	runner := &fakeRunner{outputs: map[string]string{"systemctl restart migate": ""}}
	var out bytes.Buffer
	exitCode := runCLI([]string{"reset-password", "new-pass"}, &out, &bytes.Buffer{}, runner)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	updated, err := panelcfg.Load(defaultPanelConfigPath)
	if err != nil {
		t.Fatalf("read updated config: %v", err)
	}
	if !web.IsPanelPasswordHash(updated.PanelPassword) || !web.VerifyPanelPassword(updated.PanelPassword, "new-pass") {
		t.Fatalf("password not updated as hash: %+v", updated)
	}
	info, err := os.Stat(defaultPanelConfigPath)
	if err != nil {
		t.Fatalf("stat updated config: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Fatalf("expected panel.json mode 0640, got %03o", got)
	}
	if !strings.Contains(out.String(), "面板密码已更新") || len(runner.calls) != 1 || runner.calls[0] != "systemctl restart migate" {
		t.Fatalf("unexpected reset output/calls: %q %+v", out.String(), runner.calls)
	}
}

func TestCLIEnsureManagementDirectPreservesExistingConfig(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "panel.json")
	config := `{"panel_port":9999,"database_path":"` + filepath.Join(tmp, "migate.db") + `","management_direct_enabled":false,"management_direct_hosts":["old.example"],"management_direct_ports":[2200]}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	var out bytes.Buffer
	exitCode := runCLI([]string{"ensure-management-direct", "--config", configPath, "--host", "103.193.149.217", "--port", "22"}, &out, &bytes.Buffer{}, &fakeRunner{})
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d: %s", exitCode, out.String())
	}
	updated, err := panelcfg.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if updated.ManagementDirectEnabled {
		t.Fatalf("explicit disabled flag should be preserved: %+v", updated)
	}
	if strings.Join(updated.ManagementDirectHosts, ",") != "old.example,103.193.149.217" {
		t.Fatalf("unexpected hosts: %+v", updated.ManagementDirectHosts)
	}
	if len(updated.ManagementDirectPorts) != 2 || updated.ManagementDirectPorts[0] != 22 || updated.ManagementDirectPorts[1] != 2200 {
		t.Fatalf("unexpected ports: %+v", updated.ManagementDirectPorts)
	}
}

func TestCLIURLPublicUsesDetectedIPv4(t *testing.T) {
	tmp := t.TempDir()
	oldPath := defaultPanelConfigPath
	defaultPanelConfigPath = filepath.Join(tmp, "panel.json")
	defer func() { defaultPanelConfigPath = oldPath }()
	if err := os.WriteFile(defaultPanelConfigPath, []byte(`{"panel_port":9999,"web_base_path":"/migate"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	runner := &fakeRunner{outputs: map[string]string{"curl -fsS --max-time 3 https://api.ipify.org": "203.0.113.7"}}
	var out bytes.Buffer
	exitCode := runCLI([]string{"url", "--public"}, &out, &bytes.Buffer{}, runner)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	if got := strings.TrimSpace(out.String()); got != "http://203.0.113.7:9999/migate" {
		t.Fatalf("unexpected public url: %q", got)
	}
}

func TestCLIUpdateCheckQueriesLatestRelease(t *testing.T) {
	old := Version
	Version = "v1.0.0"
	defer func() { Version = old }()
	runner := &fakeRunner{outputs: map[string]string{"/usr/local/bin/migate-install --check": "当前版本: v1.0.0\n最新版本: v1.0.1\n可更新: 是\n"}}
	var out bytes.Buffer
	exitCode := runCLI([]string{"update", "--check"}, &out, &bytes.Buffer{}, runner)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	if !strings.Contains(out.String(), "可更新") || runner.calls[0] != "/usr/local/bin/migate-install --check" {
		t.Fatalf("unexpected update check: %q %+v", out.String(), runner.calls)
	}
}

func TestCLILogsFollowAndRestartAllUseExpectedServices(t *testing.T) {
	runner := &fakeRunner{outputs: map[string]string{
		"journalctl -u migate -n 80 -f":                               "following\n",
		"systemctl restart migate":                                    "",
		"systemctl show migate-xray --property=LoadState --value":     "loaded\n",
		"systemctl restart migate-xray":                               "",
		"systemctl show migate-sing-box --property=LoadState --value": "loaded\n",
		"systemctl restart migate-sing-box":                           "",
	}}
	if code := runCLI([]string{"logs", "-f"}, &bytes.Buffer{}, &bytes.Buffer{}, runner); code != 0 {
		t.Fatalf("logs -f exit %d", code)
	}
	if code := runCLI([]string{"restart", "all"}, &bytes.Buffer{}, &bytes.Buffer{}, runner); code != 0 {
		t.Fatalf("restart all exit %d", code)
	}
	want := []string{"journalctl -u migate -n 80 -f", "systemctl restart migate", "systemctl show migate-xray --property=LoadState --value", "systemctl restart migate-xray", "systemctl show migate-sing-box --property=LoadState --value", "systemctl restart migate-sing-box"}
	if strings.Join(runner.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("unexpected calls: %+v", runner.calls)
	}
}

func TestCLIRestartAllDoesNotFallbackToLegacySingboxService(t *testing.T) {
	runner := &fakeRunner{outputs: map[string]string{
		"systemctl restart migate":                                    "",
		"systemctl show migate-xray --property=LoadState --value":     "loaded\n",
		"systemctl restart migate-xray":                               "",
		"systemctl show migate-sing-box --property=LoadState --value": "not-found\n",
	}}
	if code := runCLI([]string{"restart", "all"}, &bytes.Buffer{}, &bytes.Buffer{}, runner); code != 0 {
		t.Fatalf("restart all exit %d", code)
	}
	want := []string{
		"systemctl restart migate",
		"systemctl show migate-xray --property=LoadState --value",
		"systemctl restart migate-xray",
		"systemctl show migate-sing-box --property=LoadState --value",
	}
	if strings.Join(runner.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("unexpected calls: %+v", runner.calls)
	}
}

func TestCLIRestartAllReportsXrayRestartFailure(t *testing.T) {
	runner := &fakeRunner{
		outputs: map[string]string{
			"systemctl restart migate":                                "",
			"systemctl show migate-xray --property=LoadState --value": "loaded\n",
			"systemctl restart migate-xray":                           "Unit migate-xray.service not found\n",
		},
		errors: map[string]error{"systemctl restart migate-xray": errors.New("exit status 5")},
	}
	var stderr bytes.Buffer
	if code := runCLI([]string{"restart", "all"}, &bytes.Buffer{}, &stderr, runner); code != 1 {
		t.Fatalf("restart all should fail when Xray restart fails, got %d", code)
	}
	wantCalls := []string{"systemctl restart migate", "systemctl show migate-xray --property=LoadState --value", "systemctl restart migate-xray"}
	if strings.Join(runner.calls, "|") != strings.Join(wantCalls, "|") {
		t.Fatalf("unexpected calls after Xray failure: %+v", runner.calls)
	}
	if !strings.Contains(stderr.String(), "Unit migate-xray.service not found") || !strings.Contains(stderr.String(), "restart migate-xray failed") {
		t.Fatalf("stderr should mention xray restart failure, got %q", stderr.String())
	}
}

func TestCLIRestartAllSkipsUnmanagedXrayService(t *testing.T) {
	runner := &fakeRunner{outputs: map[string]string{
		"systemctl restart migate":                                    "",
		"systemctl show migate-xray --property=LoadState --value":     "not-found\n",
		"systemctl show migate-sing-box --property=LoadState --value": "loaded\n",
		"systemctl restart migate-sing-box":                           "",
	}}
	if code := runCLI([]string{"restart", "all"}, &bytes.Buffer{}, &bytes.Buffer{}, runner); code != 0 {
		t.Fatalf("restart all exit %d", code)
	}
	want := []string{
		"systemctl restart migate",
		"systemctl show migate-xray --property=LoadState --value",
		"systemctl show migate-sing-box --property=LoadState --value",
		"systemctl restart migate-sing-box",
	}
	if strings.Join(runner.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("unexpected calls when Xray is unmanaged: %+v", runner.calls)
	}
}

func TestCLIBackupAndRestoreUseTarWithConfigAndDataPaths(t *testing.T) {
	tmp := t.TempDir()
	oldPath := defaultPanelConfigPath
	defaultPanelConfigPath = filepath.Join(tmp, "panel.json")
	defer func() { defaultPanelConfigPath = oldPath }()
	config := `{"database_path":"/var/lib/migate/migate.db"}`
	if err := os.WriteFile(defaultPanelConfigPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	runner := &fakeRunner{outputs: map[string]string{
		"tar -czf /tmp/migate-backup.tar.gz /etc/migate /var/lib/migate/migate.db /var/lib/migate/versions.json": "",
		"tar -xzf /tmp/migate-backup.tar.gz -C /": "",
		"systemctl restart migate":                "",
	}}
	if code := runCLI([]string{"backup", "/tmp/migate-backup.tar.gz"}, &bytes.Buffer{}, &bytes.Buffer{}, runner); code != 0 {
		t.Fatalf("backup exit %d", code)
	}
	if code := runCLI([]string{"restore", "/tmp/migate-backup.tar.gz"}, &bytes.Buffer{}, &bytes.Buffer{}, runner); code != 0 {
		t.Fatalf("restore exit %d", code)
	}
	want := []string{
		"tar -czf /tmp/migate-backup.tar.gz /etc/migate /var/lib/migate/migate.db /var/lib/migate/versions.json",
		"tar -xzf /tmp/migate-backup.tar.gz -C /",
		"systemctl restart migate",
	}
	if strings.Join(runner.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("unexpected backup/restore calls: %+v", runner.calls)
	}
}

func TestCLIBackupDefaultsToRuntimeContractBackupDirectory(t *testing.T) {
	oldBackupDir := paths.BackupDir
	paths.BackupDir = "/var/lib/migate/backups"
	defer func() { paths.BackupDir = oldBackupDir }()
	path := defaultBackupPath()
	if !strings.HasPrefix(path, "/var/lib/migate/backups/migate-backup-") || !strings.HasSuffix(path, ".tar.gz") {
		t.Fatalf("unexpected default backup path: %s", path)
	}
	if got := strings.Join(backupFiles(), "|"); got != "/etc/migate|/var/lib/migate/migate.db|/var/lib/migate/versions.json" {
		t.Fatalf("unexpected backup files: %s", got)
	}
}

func TestCLIBackupCreatesDestinationDirectoryBeforeTar(t *testing.T) {
	tmp := t.TempDir()
	backupPath := filepath.Join(tmp, "missing", "migate-backup.tar.gz")
	runner := &fakeRunner{outputs: map[string]string{
		"tar -czf " + backupPath + " /etc/migate /var/lib/migate/migate.db /var/lib/migate/versions.json": "",
	}}
	if code := runCLI([]string{"backup", backupPath}, &bytes.Buffer{}, &bytes.Buffer{}, runner); code != 0 {
		t.Fatalf("backup exit %d", code)
	}
	if info, err := os.Stat(filepath.Dir(backupPath)); err != nil || !info.IsDir() {
		t.Fatalf("backup should create destination dir, stat=%v info=%+v", err, info)
	}
}

func TestCLIPortsShowsPanelAndListeningPorts(t *testing.T) {
	tmp := t.TempDir()
	oldPath := defaultPanelConfigPath
	defaultPanelConfigPath = filepath.Join(tmp, "panel.json")
	defer func() { defaultPanelConfigPath = oldPath }()
	if err := os.WriteFile(defaultPanelConfigPath, []byte(`{"panel_port":9999,"web_base_path":"/migate"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	runner := &fakeRunner{outputs: map[string]string{"ss -ltn": "LISTEN 0 4096 *:9999 *:*\nLISTEN 0 4096 *:443 *:*\n"}}
	var out bytes.Buffer
	if code := runCLI([]string{"ports"}, &out, &bytes.Buffer{}, runner); code != 0 {
		t.Fatalf("ports exit %d", code)
	}
	body := out.String()
	for _, want := range []string{"9999", "面板", "listening", "10085", "Xray Stats API", "10086", "sing-box Stats API"} {
		if !strings.Contains(body, want) {
			t.Fatalf("ports output missing %q:\n%s", want, body)
		}
	}
}

func TestCLIPanelURLNormalizesBasePath(t *testing.T) {
	cfg := panelcfg.Config{PanelPort: 9999, WebPath: "migate"}
	if got := panelURL(cfg, "SERVER_IP"); got != "http://SERVER_IP:9999/migate" {
		t.Fatalf("unexpected normalized url: %q", got)
	}
}

func TestCommandModeKeepsLegacyConfigArgsServingButBareCommandIsCLI(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want commandMode
	}{
		{args: []string{}, want: modeCLI},
		{args: []string{"status"}, want: modeCLI},
		{args: []string{"serve", "--config", "/etc/migate/panel.json"}, want: modeServe},
		{args: []string{"--config", "/etc/migate/panel.json"}, want: modeServe},
	} {
		if got := detectCommandMode(tc.args); got != tc.want {
			t.Fatalf("%v: got %v want %v", tc.args, got, tc.want)
		}
	}
}

func TestExecCmdPreservesStderrOnFailure(t *testing.T) {
	out, err := execCmd("sh", "-c", "printf 'xray stderr detail' >&2; exit 1")
	if err == nil {
		t.Fatal("expected command failure")
	}
	if !strings.Contains(out, "xray stderr detail") {
		t.Fatalf("execCmd must preserve stderr, got %q", out)
	}
}

type fakeStatsClient struct {
	stats map[string]*xray.ClientStats
	err   error
}

func (c *fakeStatsClient) QueryAllStats(ctx context.Context) (map[string]*xray.ClientStats, error) {
	if c.err != nil {
		return nil, c.err
	}
	if c.stats == nil {
		return map[string]*xray.ClientStats{}, nil
	}
	return c.stats, nil
}

func (c *fakeStatsClient) Close() error { return nil }

type fakeRunner struct {
	outputs map[string]string
	errors  map[string]error
	calls   []string
}

func (r *fakeRunner) Run(name string, args ...string) (string, error) {
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	r.calls = append(r.calls, key)
	if err, ok := r.errors[key]; ok {
		return r.outputs[key], err
	}
	if out, ok := r.outputs[key]; ok {
		return out, nil
	}
	return "", errors.New("unexpected command: " + key)
}
