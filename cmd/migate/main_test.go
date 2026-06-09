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
	config := `{"panel_port":9999,"web_base_path":"/","database_path":"` + databasePath + `"}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	router, cleanup, err := routerFromConfig(configPath)
	if err != nil {
		t.Fatalf("router from config: %v", err)
	}
	defer cleanup()

	payload := []byte(`{"remark":"真机入口","protocol":"vless","port":8443,"network":"tcp","security":"reality"}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/inbounds", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
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

func TestRouterFromPanelConfigSkipsAuthWhenNoCredentials(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "panel_noauth.json")
	config := `{"panel_port":9999,"database_path":"` + filepath.Join(tmp, "migate.db") + `"}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	router, cleanup, err := routerFromConfig(configPath)
	if err != nil {
		t.Fatalf("router from config: %v", err)
	}
	defer cleanup()

	// Without cookie -> 200 (auth is off)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 (no auth) when credentials absent, got %d", response.Code)
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
		"mg status",
		"mg logs",
		"mg restart",
		"mg url",
		"mg uninstall",
		"migate serve --config /etc/migate/panel.json",
	} {
		if !strings.Contains(menu, want) {
			t.Fatalf("CLI menu missing %q:\n%s", want, menu)
		}
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
	if !strings.Contains(out.String(), "migate: active") || !strings.Contains(out.String(), "migate-singbox: inactive") {
		t.Fatalf("unexpected status output: %s", out.String())
	}
	if len(runner.calls) != 2 {
		t.Fatalf("expected 2 systemctl calls, got %+v", runner.calls)
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
