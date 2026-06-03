package web_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/imzyb/MiGate/internal/web"
)

func TestRouterServesStaticPanelAndHealthAPI(t *testing.T) {
	router := web.NewRouter()

	page := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(page, req)
	if page.Code != http.StatusOK {
		t.Fatalf("expected 200 for panel, got %d: %s", page.Code, page.Body.String())
	}
	body := page.Body.String()
	for _, want := range []string{"MiGate", "Go Lite", "概览", "入站", "客户端", "订阅", "Xray", "VLESS", "VMess", "Trojan", "Shadowsocks"} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing %q: %s", want, body)
		}
	}

	health := httptest.NewRecorder()
	healthReq := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	router.ServeHTTP(health, healthReq)
	if health.Code != http.StatusOK {
		t.Fatalf("expected health 200, got %d: %s", health.Code, health.Body.String())
	}
	if !strings.Contains(health.Body.String(), `"status":"ok"`) || !strings.Contains(health.Body.String(), `"mode":"go-lite"`) {
		t.Fatalf("unexpected health body: %s", health.Body.String())
	}
}

func TestPanelWiresInboundManagementToAPI(t *testing.T) {
	router := web.NewRouter()
	page := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(page, req)
	if page.Code != http.StatusOK {
		t.Fatalf("expected 200 for panel, got %d: %s", page.Code, page.Body.String())
	}
	body := page.Body.String()
	for _, want := range []string{
		`id="inbound-count"`,
		`id="client-count"`,
		`id="inbound-list"`,
		`id="inbound-form"`,
		`name="remark"`,
		`name="protocol"`,
		`name="port"`,
		`loadInbounds()`,
		`fetch('/api/inbounds')`,
		`method: 'POST'`,
		`renderInbounds`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel inbound management missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"npm", "node_modules", "openvpn", "leak-check", "remote/readiness"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Fatalf("panel should keep Go Lite scope and avoid %q: %s", forbidden, body)
		}
	}
}

func TestRouterDoesNotServeLegacyHeavyRoutes(t *testing.T) {
	router := web.NewRouter()
	for _, path := range []string{"/api/remote/readiness", "/api/leak-check", "/api/egress/status", "/api/openvpn/status", "/api/proxy/status"} {
		response := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		router.ServeHTTP(response, req)
		if response.Code != http.StatusNotFound {
			t.Fatalf("legacy heavy route %s should be 404, got %d", path, response.Code)
		}
	}
}
