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
	for _, want := range []string{"MiGate", "概览", "入站", "客户端", "订阅", "Xray", "VLESS", "VMess", "Trojan", "Shadowsocks"} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"MiGate Go Lite", "Go Lite"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("panel should use MiGate as the product name, found %q: %s", forbidden, body)
		}
	}

	health := httptest.NewRecorder()
	healthReq := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	router.ServeHTTP(health, healthReq)
	if health.Code != http.StatusOK {
		t.Fatalf("expected health 200, got %d: %s", health.Code, health.Body.String())
	}
	if !strings.Contains(health.Body.String(), `"status":"ok"`) || !strings.Contains(health.Body.String(), `"mode":"single-binary"`) {
		t.Fatalf("unexpected health body: %s", health.Body.String())
	}
	if strings.Contains(health.Body.String(), "go-lite") {
		t.Fatalf("health API should not expose go-lite as the product mode: %s", health.Body.String())
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
			t.Fatalf("panel should keep lightweight single-binary scope and avoid %q: %s", forbidden, body)
		}
	}
}

func TestPanelWiresClientManagement(t *testing.T) {
	router := web.NewRouter()
	page := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(page, req)
	if page.Code != http.StatusOK {
		t.Fatalf("expected 200 for panel, got %d: %s", page.Code, page.Body.String())
	}
	body := page.Body.String()
	for _, want := range []string{
		`id="clients"`,
		`id="client-form"`,
		`name="email"`,
		`id="client-list"`,
		`loadClients()`,
		`renderClients`,
		`订阅链接`,
		`copy-link`,
		`subscriptionHost`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel client management missing %q: %s", want, body)
		}
	}
}

func TestPanelWiresDeleteInboundButton(t *testing.T) {
	router := web.NewRouter()
	page := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(page, req)
	if page.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", page.Code)
	}
	body := page.Body.String()
	for _, want := range []string{
		`deleteInbound`,
		`确认删除`,
		`method: 'DELETE'`,
		`/api/inbounds/`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel inbound delete missing %q: %s", want, body)
		}
	}
}

func TestPanelWiresDeleteClientButton(t *testing.T) {
	router := web.NewRouter()
	page := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(page, req)
	if page.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", page.Code)
	}
	body := page.Body.String()
	for _, want := range []string{
		`deleteClient`,
		`确认删除`,
		`method: 'DELETE'`,
		`/api/inbounds/`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel client delete missing %q: %s", want, body)
		}
	}
}

func TestPanelWiresAdvancedWebUI(t *testing.T) {
	router := web.NewRouter()
	page := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(page, req)
	if page.Code != http.StatusOK {
		t.Fatalf("expected 200 for panel, got %d", page.Code)
	}
	body := page.Body.String()

	// Network is a select with all transport options
	for _, want := range []string{
		`<select name="network"`,
		`value="tcp"`, `value="ws"`, `value="kcp"`,
		`value="grpc"`, `value="quic"`, `value="h2"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel advanced UI missing network select option %q", want)
		}
	}

	// Dynamic config fields present
	for _, want := range []string{
		`id="ws-settings"`,
		`id="reality-settings"`,
		`id="ss-settings"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel advanced UI missing dynamic field container %q", want)
		}
	}

	// Toast notification function exists
	if !strings.Contains(body, "showToast(") {
		t.Fatalf("panel advanced UI missing showToast function")
	}
	if !strings.Contains(body, "toast-container") {
		t.Fatalf("panel advanced UI missing toast-container div")
	}

	// JS function to show/hide conditional fields
	for _, want := range []string{"updateDynamicFields("} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel advanced UI missing dynamic field logic %q", want)
		}
	}

	// All native alert/confirm replaced with toast and modal confirm
	if strings.Contains(body, "alert(") {
		t.Fatalf("panel should not use native alert(), found alert(")
	}
	if strings.Contains(body, "confirm(") && !strings.Contains(body, "showConfirm(") {
		t.Fatalf("panel should not use native confirm(), found confirm(")
	}
	if !strings.Contains(body, "showConfirm(") {
		t.Fatalf("panel should have showConfirm() to replace native confirm()")
	}

	// Edit and toggle buttons for inbound and client rows
	for _, want := range []string{"toggleInbound(", "editInbound(", "toggleClient(", "editClient("} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing edit/toggle function %q", want)
		}
	}

	// No redundant hero title/subtitle
	if strings.Contains(body, `#hero-section`) {
		t.Fatalf("panel should not have redundant hero section")
	}

	// Nav links work with section switching
	for _, want := range []string{`href="/"`, `href="/#inbounds"`, `href="/#clients"`, `href="/#subscriptions"`, `href="/#xray"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing nav link %q", want)
		}
	}
	if !strings.Contains(body, "navigateTo(") {
		t.Fatalf("panel missing navigateTo function for nav switching")
	}

	// Confirm overlay hidden class must use higher-specificity selector
	if !strings.Contains(body, "#confirm-overlay.hidden") {
		t.Fatalf("panel CSS must use #confirm-overlay.hidden (not .hidden) to override ID selector display:flex")
	}

	// New sections: subscriptions and xray
	for _, want := range []string{`id="subscriptions"`, `id="xray"`, `id="sub-inbound-summary"`, `id="xray-status"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing section/element %q", want)
		}
	}

	// Xray and subscription JS functions
	for _, want := range []string{"fetchXrayStatus", "applyXrayConfig", "loadSubSummary"} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing JS function %q", want)
		}
	}

	// Each nav shows exactly one section (no overlap)
	t.Run("navigateToShowsOnlySelectedSection", func(t *testing.T) {
		if !strings.Contains(body, "el.id === sectionId") {
			t.Fatalf("navigateTo must compare el.id === sectionId, not sectionId === 'overview' OR condition")
		}
	})

	// Edit modals replace prompt()
	for _, want := range []string{"edit-inbound-overlay", "edit-client-overlay", "ei-remark", "ei-protocol", "ei-port", "ei-network", "ei-security", "ec-email"} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing edit modal element %q", want)
		}
	}
	for _, want := range []string{"saveEditInbound", "closeEditInbound", "saveEditClient", "closeEditClient", "eiUpdateDynamicFields"} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing edit modal JS function %q", want)
		}
	}
	if strings.Contains(body, "prompt(") && !strings.Contains(body, "edit-inbound-overlay") {
		t.Fatalf("panel should not use prompt(), should use modal overlays")
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
