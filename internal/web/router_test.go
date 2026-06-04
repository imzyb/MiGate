package web_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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

	// Vercel-style shell and design tokens
	for _, want := range []string{
		`fonts.googleapis.com/css2?family=Geist`,
		`--bg: #ffffff;`,
		`--fg: #171717;`,
		`--surface: #ffffff;`,
		`--muted: #666666;`,
		`--line: rgba(0,0,0,.08);`,
		`--shadow-sm: 0 0 0 1px rgba(0,0,0,.08);`,
		`--shadow-md: 0 0 0 1px rgba(0,0,0,.08), 0 2px 2px rgba(0,0,0,.04), 0 8px 8px -8px rgba(0,0,0,.04);`,
		`font-family:'Geist',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;`,
		`font-family:'Geist Mono',ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace;`,
		`class="app-shell"`,
		`class="sidebar"`,
		`class="topbar"`,
		`class="card panel"`,
		`class="section-heading"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel vercel-style shell missing %q", want)
		}
	}

	// Unified density/design-token contract for cards, forms, controls, and rows.
	for _, want := range []string{
		`--space-1: 4px;`,
		`--space-2: 8px;`,
		`--space-3: 12px;`,
		`--space-4: 16px;`,
		`--space-5: 20px;`,
		`--space-6: 24px;`,
		`--control-height: 40px;`,
		`--control-radius: var(--radius-sm);`,
		`--text-xs: 12px;`,
		`--text-sm: 13px;`,
		`--text-md: 14px;`,
		`--text-lg: 16px;`,
		`--panel-padding: var(--space-5);`,
		`--row-padding: var(--space-4);`,
		`.ui-control`,
		`input, select, textarea {`,
		`min-height:var(--control-height);`,
		`font-size:var(--text-md);`,
		`.panel, .card {`,
		`padding:var(--panel-padding);`,
		`.form-grid {`,
		`gap:var(--space-4);`,
		`.field-group { display:grid; gap:var(--space-2);`,
		`.field-label { color:var(--fg); font-size:var(--text-sm);`,
		`.field-help { color:var(--muted); font-size:var(--text-xs);`,
		`.resource-row {`,
		`padding:var(--row-padding);`,
		`.resource-main { min-width:0; display:grid; gap:var(--space-2);`,
		`.resource-meta {`,
		`font-size:var(--text-xs);`,
		`.icon-btn, .danger-icon-btn {`,
		`min-height:32px;`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing unified density/design-token contract %q", want)
		}
	}

	// Edit modals use the same form-grid/field-group system as main panel forms.
	for _, want := range []string{
		`.modal-title`,
		`.modal-form`,
		`#edit-inbound-form.modal-form`,
		`#edit-client-form.modal-form`,
		`<form id="edit-inbound-form" class="form-grid modal-form" onsubmit="return false">`,
		`<form id="edit-client-form" class="form-grid modal-form" onsubmit="return false">`,
		`<label class="field-label" for="ei-remark">入站备注</label>`,
		`<label class="field-label" for="ei-protocol">协议</label>`,
		`<label class="field-label" for="ei-port">监听端口</label>`,
		`<label class="field-label" for="ei-network">传输</label>`,
		`<label class="field-label" for="ei-security">安全</label>`,
		`<label class="field-label" for="ec-email">客户端标识</label>`,
		`<label class="field-label" for="ec-traffic-limit">流量限额</label>`,
		`<label class="field-label" for="ec-expiry-at">过期时间</label>`,
		`class="advanced-fieldset field-group span-2 hidden"`,
		`class="form-actions modal-actions"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing unified edit-modal form contract %q", want)
		}
	}

	// Edit inbound dynamic advanced fields are grouped as scan-friendly cards.
	for _, want := range []string{
		`.advanced-fieldset`,
		`.advanced-fieldset-title`,
		`.advanced-fieldset-copy`,
		`class="advanced-fieldset field-group span-2 hidden"`,
		`<div class="advanced-fieldset-title">WebSocket 设置</div>`,
		`<div class="advanced-fieldset-title">gRPC 设置</div>`,
		`<div class="advanced-fieldset-title">XHTTP 设置</div>`,
		`<div class="advanced-fieldset-title">REALITY 设置</div>`,
		`<div class="advanced-fieldset-title">Shadowsocks 设置</div>`,
		`<div class="advanced-fieldset-title">TLS 设置</div>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing advanced edit-fieldset contract %q", want)
		}
	}

	// Network is a select with all transport options
	for _, want := range []string{
		`<select name="network"`,
		`value="tcp"`, `value="ws"`, `value="kcp"`,
		`value="grpc"`, `value="quic"`, `value="h2"`, `value="xhttp"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel advanced UI missing network select option %q", want)
		}
	}

	// Dynamic config fields present
	for _, want := range []string{
		`id="ws-settings"`,
		`id="grpc-settings"`,
		`id="xhttp-settings"`,
		`id="reality-settings"`,
		`id="ss-settings"`,
		`id="tls-settings"`,
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

	// gRPC dynamic field in edit modal
	for _, want := range []string{
		`id="ei-grpc-settings"`,
		`id="ei-grpc-service-name"`,
		`grpc_service_name:`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing gRPC edit field %q", want)
		}
	}

	// TLS edit modal fields
	for _, want := range []string{
		`id="ei-tls-settings"`,
		`id="ei-tls-cert-file"`,
		`id="ei-tls-key-file"`,
		`tls_cert_file:`,
		`tls_key_file:`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing TLS edit field %q", want)
		}
	}

	// XHTTP create/edit modal fields
	for _, want := range []string{
		`id="xhttp-settings"`,
		`name="xhttp_path"`,
		`name="xhttp_mode"`,
		`id="ei-xhttp-settings"`,
		`id="ei-xhttp-path"`,
		`id="ei-xhttp-mode"`,
		`xhttp_path:`,
		`xhttp_mode:`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing XHTTP field %q", want)
		}
	}

	// No redundant hero title/subtitle
	if strings.Contains(body, `#hero-section`) {
		t.Fatalf("panel should not have redundant hero section")
	}

	// Nav links work with section switching
	for _, want := range []string{`href="/"`, `href="/#inbounds"`, `href="/#clients"`, `href="/#subscriptions"`, `href="/#xray"`, `href="/#settings"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing nav link %q", want)
		}
	}
	if !strings.Contains(body, "navigateTo(") {
		t.Fatalf("panel missing navigateTo function for nav switching")
	}
	if !strings.Contains(body, `main > section{display:none}`) {
		t.Fatalf("panel should hide all sections by default via CSS to avoid SPA flash")
	}
	if !strings.Contains(body, `#overview{display:block}`) {
		t.Fatalf("panel should show overview by default via CSS")
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

	// Settings section
	for _, want := range []string{`href="/#settings"`, `id="settings"`, "loadSettings", "saveSettings"} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing settings element %q", want)
		}
	}

	// Xray config preview
	for _, want := range []string{"previewXrayConfig", "xray-config-preview"} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing config preview element %q", want)
		}
	}

	// Vercel-style scan-friendly resource rows
	for _, want := range []string{
		`.resource-row`,
		`.resource-main`,
		`.resource-title`,
		`.resource-meta`,
		`.status-badge`,
		`.status-badge.enabled`,
		`.status-badge.disabled`,
		`.resource-actions`,
		`.icon-btn`,
		`.danger-icon-btn`,
		`.traffic-track`,
		`.traffic-fill`,
		`class="resource-row"`,
		`class="resource-main"`,
		`class="resource-title"`,
		`class="resource-meta"`,
		`status-badge ' + enabledClass`,
		`const enabledClass = inbound.enabled ? 'enabled' : 'disabled';`,
		`const badgeClass = c.enabled && !isExpired && !isOverLimit ? 'enabled' : 'disabled';`,
		`class="resource-actions"`,
		`class="icon-btn"`,
		`class="danger-icon-btn"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing Vercel-style resource row contract %q", want)
		}
	}

	// Vercel-style form field groups
	for _, want := range []string{
		`.form-grid`,
		`.field-group`,
		`.field-label`,
		`.field-help`,
		`.form-actions`,
		`class="form-grid"`,
		`class="field-group"`,
		`class="field-label"`,
		`class="field-help"`,
		`class="form-actions"`,
		`for="inbound-remark"`,
		`id="inbound-remark"`,
		`for="client-email"`,
		`id="client-email"`,
		`for="set-panel-port"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing Vercel-style form contract %q", want)
		}
	}

	// Vercel-style empty/loading states
	for _, want := range []string{
		`.empty-state`,
		`.empty-state-title`,
		`.empty-state-copy`,
		`.empty-state-actions`,
		`function renderEmptyState`,
		`renderEmptyState('暂无入站'`,
		`renderEmptyState('选择入站'`,
		`renderEmptyState('暂无客户端'`,
		`renderEmptyState('正在加载订阅概况'`,
		`class="empty-state"`,
		`class="empty-state-title"`,
		`class="empty-state-copy"`,
		`class="empty-state-actions"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing empty-state contract %q", want)
		}
	}

	// Vercel-style notice/status feedback cards
	for _, want := range []string{
		`.notice`,
		`.notice-title`,
		`.notice-copy`,
		`.notice.success`,
		`.notice.error`,
		`function renderNotice`,
		`renderNotice('正在应用'`,
		`renderNotice('应用完成'`,
		`renderNotice('应用失败'`,
		`renderNotice('数据库'`,
		`renderNotice('设置不可用'`,
		`id="xray-result" class="notice-slot"`,
		`id="settings-status" class="notice-slot"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing notice/status feedback contract %q", want)
		}
	}

	// Xray and settings operation buttons use one shared action toolbar layout.
	for _, want := range []string{
		`.action-toolbar`,
		`.toolbar-copy`,
		`.toolbar-actions`,
		`class="action-toolbar xray-toolbar"`,
		`class="toolbar-copy"`,
		`class="toolbar-actions"`,
		`class="action-toolbar settings-toolbar span-2"`,
		`应用、预览与刷新统一集中在右侧操作区。`,
		`保存配置后按需重启 MiGate 服务。`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing shared action-toolbar contract %q", want)
		}
	}

	// Toggle toast must use the toggled entity state, not an undefined newEnabled variable
	if strings.Contains(body, "newEnabled") {
		t.Fatalf("panel toggle handlers must not reference undefined newEnabled")
	}
	for _, want := range []string{
		`showToast('入站 ' + (inbound.enabled ? '已启用' : '已禁用'), 'success')`,
		`showToast('客户端 ' + (client.enabled ? '已启用' : '已禁用'), 'success')`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing safe toggle toast expression %q", want)
		}
	}

	// Traffic/expiry UI elements
	for _, want := range []string{"ec-traffic-limit", "ec-expiry-at", "formatBytes", "traffic_limit", "bar-low"} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing traffic/expiry element %q", want)
		}
	}

	// Overview traffic stats
	for _, want := range []string{"total-traffic", "xray-status-metric", "formatBytes"} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing overview stat element %q", want)
		}
	}
}

func TestSettingsAPI(t *testing.T) {
	tmp := t.TempDir()
	configPath := tmp + "/panel.json"
	config := `{"panel_port":9999,"panel_username":"admin","panel_password":"secret","web_base_path":"/","database_path":"/tmp/migate.db"}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	router := web.NewRouter(web.WithConfigDir(tmp))

	// GET should return settings without password, but has_password=true
	// GET returns settings including has_password
	t.Run("GET returns settings including has_password", func(t *testing.T) {
		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
		router.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.Code)
		}
		var data map[string]interface{}
		if err := json.Unmarshal(resp.Body.Bytes(), &data); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if _, ok := data["panel_password"]; ok {
			t.Fatal("GET /api/settings should not expose panel_password")
		}
		if data["has_password"] != true {
			t.Fatal("GET /api/settings should set has_password=true")
		}
		if data["panel_port"] != float64(9999) {
			t.Fatalf("expected panel_port=9999, got %v", data["panel_port"])
		}
	})

	// PUT saves settings
	t.Run("PUT saves settings", func(t *testing.T) {
		body := `{"panel_port":8888,"panel_username":"newadmin","panel_password":"newpass","web_base_path":"/panel/"}`
		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
		}

		// Verify written to file
		b, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("read config: %v", err)
		}
		var saved map[string]interface{}
		if err := json.Unmarshal(b, &saved); err != nil {
			t.Fatalf("unmarshal saved: %v", err)
		}
		if saved["panel_port"] != float64(8888) {
			t.Fatalf("expected panel_port=8888, got %v", saved["panel_port"])
		}
		if saved["panel_username"] != "newadmin" {
			t.Fatalf("expected panel_username=newadmin, got %v", saved["panel_username"])
		}
		if saved["panel_password"] != "newpass" {
			t.Fatalf("expected panel_password=newpass, got %v", saved["panel_password"])
		}
	})

	// PUT preserves existing password when empty
	t.Run("PUT preserves existing password", func(t *testing.T) {
		body := `{"panel_port":7777,"panel_username":"admin","panel_password":""}`
		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.Code)
		}

		b, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("read config: %v", err)
		}
		var saved map[string]interface{}
		if err := json.Unmarshal(b, &saved); err != nil {
			t.Fatalf("unmarshal saved: %v", err)
		}
		if saved["panel_password"] != "newpass" {
			t.Fatalf("expected password to be preserved as 'newpass', got %v", saved["panel_password"])
		}
	})
}

func TestSettingsPreservesDatabasePath(t *testing.T) {
	tmp := t.TempDir()
	configPath := tmp + "/panel.json"
	// Pre-seed config with database_path
	initial := `{"panel_port":9999,"panel_username":"admin","panel_password":"secret","database_path":"/data/migate.db"}`
	if err := os.WriteFile(configPath, []byte(initial), 0o600); err != nil {
		t.Fatalf("write initial config: %v", err)
	}
	router := web.NewRouter(web.WithConfigDir(tmp))

	// PUT without database_path should preserve it
	resp := httptest.NewRecorder()
	body := `{"panel_port":8888,"panel_username":"newadmin"}`
	req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}

	b, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var saved map[string]interface{}
	if err := json.Unmarshal(b, &saved); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if saved["database_path"] != "/data/migate.db" {
		t.Fatalf("expected database_path to be preserved, got %v", saved["database_path"])
	}
	if saved["panel_port"] != float64(8888) {
		t.Fatalf("expected panel_port=8888, got %v", saved["panel_port"])
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
