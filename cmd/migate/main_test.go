package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/imzyb/MiGate/internal/xray"
)

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
	req.AddCookie(sessionCookie)
	router.ServeHTTP(response, req)

	if response.Code != http.StatusCreated {
		t.Fatalf("expected configured store to create inbound, got %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"remark":"真机入口"`) {
		t.Fatalf("create response missing inbound: %s", response.Body.String())
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

	// Without cookie -> login page
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 login page without auth, got %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), "面板登录") {
		t.Fatalf("expected login page without auth, got: %s", response.Body.String())
	}

	// Login -> 200 with cookie
	loginResp := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(`{"username":"admin","password":"secret"}`)))
	loginReq.Header.Set("Content-Type", "application/json")
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
		{path: "/migate", want: http.StatusOK},
		{path: "/migate/", want: http.StatusOK},
	} {
		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		router.ServeHTTP(resp, req)
		if resp.Code != tc.want {
			t.Fatalf("%s: expected %d, got %d: %s", tc.path, tc.want, resp.Code, resp.Body.String())
		}
		if tc.path == "/migate" || tc.path == "/migate/" {
			if !strings.Contains(resp.Body.String(), "面板登录") {
				t.Fatalf("%s: expected login page for unauthenticated panel root, got: %s", tc.path, resp.Body.String())
			}
		}
	}
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

func TestCLIStatusUsesSystemctlWithoutStartingServer(t *testing.T) {
	runner := &fakeRunner{outputs: map[string]string{
		"systemctl is-active migate":         "active\n",
		"systemctl is-active migate-singbox": "inactive\n",
	}}
	var out bytes.Buffer
	exitCode := runCLI([]string{"status"}, &out, &bytes.Buffer{}, runner)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	if !strings.Contains(out.String(), "MiGate 面板: 运行中") || !strings.Contains(out.String(), "sing-box: 已停止") {
		t.Fatalf("unexpected status output: %s", out.String())
	}
	if len(runner.calls) != 2 {
		t.Fatalf("expected 2 systemctl calls, got %+v", runner.calls)
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
		"systemctl is-active migate":         "active\n",
		"systemctl is-active migate-singbox": "inactive\n",
	}}
	var out bytes.Buffer
	exitCode := runCLI([]string{"--lang", "en", "status"}, &out, &bytes.Buffer{}, runner)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	if !strings.Contains(out.String(), "MiGate Panel: running") || !strings.Contains(out.String(), "sing-box: stopped") {
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
	defaultPanelConfigPath = filepath.Join(tmp, "panel.json")
	defer func() { defaultPanelConfigPath = oldPath }()
	config := `{"panel_port":9999,"web_base_path":"/migate","database_path":"` + filepath.Join(tmp, "migate.db") + `","xray_config_path":"` + filepath.Join(tmp, "xray.json") + `"}`
	if err := os.WriteFile(defaultPanelConfigPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "migate.db"), []byte("db"), 0o600); err != nil {
		t.Fatalf("write db: %v", err)
	}
	runner := &fakeRunner{outputs: map[string]string{
		"systemctl is-active migate":         "active\n",
		"systemctl is-active migate-singbox": "inactive\n",
		"xray version":                       "Xray 26.3.27\n",
		"sing-box version":                   "sing-box version 1.13.13\n",
		"ss -ltn":                            "LISTEN 0 4096 *:9999 *:*\n",
		"free -m":                            "Mem: 900 400 500\nSwap: 512 0 512\n",
		"df -h /":                            "/dev/sda1 50G 10G 40G 20% /\n",
	}}
	var out bytes.Buffer
	exitCode := runCLI([]string{"doctor"}, &out, &bytes.Buffer{}, runner)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	body := out.String()
	for _, want := range []string{"MiGate 诊断", "MiGate 面板: 运行中", "WebUI: http://SERVER_IP:9999/migate", "Xray: 已安装", "sing-box: 已安装", "配置文件: 正常", "数据库: 正常", "内存", "磁盘"} {
		if !strings.Contains(body, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, body)
		}
	}
}

func TestCLIInfoShowsPanelDetailsWithoutPassword(t *testing.T) {
	tmp := t.TempDir()
	oldPath := defaultPanelConfigPath
	defaultPanelConfigPath = filepath.Join(tmp, "panel.json")
	defer func() { defaultPanelConfigPath = oldPath }()
	config := `{"panel_port":9999,"panel_username":"admin","panel_password":"secret","web_base_path":"/migate","database_path":"/usr/local/migate/migate.db"}`
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
	for _, want := range []string{"MiGate 信息", "版本: v1.2.3", "WebUI: http://SERVER_IP:9999/migate", "用户名: admin", "配置文件: " + defaultPanelConfigPath, "数据库: /usr/local/migate/migate.db", "mg reset-password"} {
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
	updated, err := readPanelConfig(defaultPanelConfigPath)
	if err != nil {
		t.Fatalf("read updated config: %v", err)
	}
	if updated.PanelPassword != "new-pass" {
		t.Fatalf("password not updated: %+v", updated)
	}
	if !strings.Contains(out.String(), "面板密码已更新") || len(runner.calls) != 1 || runner.calls[0] != "systemctl restart migate" {
		t.Fatalf("unexpected reset output/calls: %q %+v", out.String(), runner.calls)
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
		"journalctl -u migate -n 80 -f":    "following\n",
		"systemctl restart migate":         "",
		"systemctl restart migate-singbox": "",
	}}
	if code := runCLI([]string{"logs", "-f"}, &bytes.Buffer{}, &bytes.Buffer{}, runner); code != 0 {
		t.Fatalf("logs -f exit %d", code)
	}
	if code := runCLI([]string{"restart", "all"}, &bytes.Buffer{}, &bytes.Buffer{}, runner); code != 0 {
		t.Fatalf("restart all exit %d", code)
	}
	want := []string{"journalctl -u migate -n 80 -f", "systemctl restart migate", "systemctl restart migate-singbox"}
	if strings.Join(runner.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("unexpected calls: %+v", runner.calls)
	}
}

func TestCLIBackupAndRestoreUseTarWithConfigAndDataPaths(t *testing.T) {
	tmp := t.TempDir()
	oldPath := defaultPanelConfigPath
	defaultPanelConfigPath = filepath.Join(tmp, "panel.json")
	defer func() { defaultPanelConfigPath = oldPath }()
	config := `{"database_path":"/usr/local/migate/migate.db","xray_config_path":"/usr/local/migate/xray.json"}`
	if err := os.WriteFile(defaultPanelConfigPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	runner := &fakeRunner{outputs: map[string]string{
		"tar -czf /tmp/migate-backup.tar.gz " + defaultPanelConfigPath + " /usr/local/migate/migate.db /usr/local/migate/xray.json /etc/sing-box/config.json": "",
		"tar -xzf /tmp/migate-backup.tar.gz -C /": "",
		"systemctl restart migate":                "",
	}}
	if code := runCLI([]string{"backup", "/tmp/migate-backup.tar.gz"}, &bytes.Buffer{}, &bytes.Buffer{}, runner); code != 0 {
		t.Fatalf("backup exit %d", code)
	}
	if code := runCLI([]string{"restore", "/tmp/migate-backup.tar.gz"}, &bytes.Buffer{}, &bytes.Buffer{}, runner); code != 0 {
		t.Fatalf("restore exit %d", code)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("unexpected backup/restore calls: %+v", runner.calls)
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
	for _, want := range []string{"9999", "面板", "listening"} {
		if !strings.Contains(body, want) {
			t.Fatalf("ports output missing %q:\n%s", want, body)
		}
	}
}

func TestCLIPanelURLNormalizesBasePath(t *testing.T) {
	cfg := panelConfig{PanelPort: 9999, WebPath: "migate"}
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

func TestUsableStatsClientFallsBackToStubWhenProbeFails(t *testing.T) {
	client := usableStatsClient(context.Background(), &fakeStatsClient{err: errors.New("stats unavailable")})
	if !xray.StatsClientIsStub(client) {
		t.Fatalf("expected stub stats client when probe fails, got %T", client)
	}
}

func TestUsableStatsClientKeepsRealClientWhenProbeSucceeds(t *testing.T) {
	real := &fakeStatsClient{stats: map[string]*xray.ClientStats{}}
	client := usableStatsClient(context.Background(), real)
	if client != real {
		t.Fatalf("expected real stats client to be kept, got %T", client)
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
