package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
