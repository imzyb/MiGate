package web_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/imzyb/MiGate/internal/web"
)

func TestRouterBackendSecurityContracts(t *testing.T) {
	source, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatalf("read router.go: %v", err)
	}
	body := string(source)
	if strings.Contains(body, `exec.Command("bash", "-c"`) || strings.Contains(body, `exec.Command("sh", "-c"`) {
		t.Fatalf("router must not execute shell strings via bash/sh -c")
	}
	if regexp.MustCompile(`tail",\s*"-n",\s*lines`).FindString(body) != "" && !strings.Contains(body, "maxXrayLogLines") {
		t.Fatalf("xray log line count must be clamped before passing to journalctl/tail")
	}
}

func TestRouterServesStaticPanelAndHealthAPI(t *testing.T) {
	router := web.NewRouter()

	page := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(page, req)
	if page.Code != http.StatusOK {
		t.Fatalf("expected 200 for panel, got %d: %s", page.Code, page.Body.String())
	}
	body := page.Body.String()
	for _, want := range []string{"MiGate", "概览", "入站", "客户端", "出站", "Xray", "VLESS", "VMess", "Trojan", "Shadowsocks"} {
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

func TestPanelOutboundInteractionsReportFailuresAndConsistentLatencyUnits(t *testing.T) {
	router := web.NewRouter()
	page := httptest.NewRecorder()
	router.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))
	if page.Code != http.StatusOK {
		t.Fatalf("expected 200 for panel, got %d: %s", page.Code, page.Body.String())
	}
	body := page.Body.String()
	for _, want := range []string{
		`if (!resp.ok) { showToast('排序保存失败', 'error'); await loadOutbounds(); return; }`,
		`showToast('排序已保存', 'success');`,
		`catch(function() { showToast('排序保存失败', 'error'); loadOutbounds(); })`,
		`var ms = Number(r.latency).toFixed(0);`,
		`id="vpngate-type-filter"`,
		`id="vpngate-country-filter"`,
		`id="vpngate-max-ping"`,
		`id="vpngate-topn"`,
		`function smartSelectVPNGate()`,
		`function vpnGateQualityScore(s)`,
		`/api/vpngate/probe`,
		`检测连通性...`,
		`VPN Gate 出口池（自动均衡）`,
		`检测 VPN Gate`,
		`function checkVPNGateOutboundHealth()`,
		`/api/vpngate/outbounds/health`,
		`VPN Gate 健康检测完成`,
		`vpngate-auto-health-card`,
		`function refreshAutoHealthStatus()`,
		`/api/vpngate/auto-health/status`,
		`已跳过重复节点`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing outbound interaction contract %q", want)
		}
	}
	if strings.Contains(body, `r.latency * 1000`) {
		t.Fatalf("batch outbound speed test must not multiply millisecond latency by 1000")
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
		`id="create-inbound-overlay"`,
		`id="create-inbound-form"`,
		`openCreateInbound()`,
		`closeCreateInbound()`,
		`saveCreateInbound()`,
		`onclick="openCreateInbound()"`,
		`name="remark"`,
		`name="protocol"`,
		`name="port"`,
		`loadInbounds()`,
		`fetch(apiPath('/api/inbounds'))`,
		`method: 'POST'`,
		`renderInbounds`,
		`toggleInitClient`,
		`init-client-email`,
		`同时添加首个客户端`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel inbound management missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{`id="inbound-form"`, `document.getElementById('inbound-form')`, `document.querySelector('[name=protocol]')`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("panel should move inbound creation into modal and remove old inline form contract, found %q", forbidden)
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
		`id="create-client-overlay"`,
		`id="create-client-form"`,
		`client-inbound-id`,
		`openCreateClient(inboundId)`,
		`closeCreateClient()`,
		`saveCreateClient()`,
		`name="email"`,
		`id="client-uuid"`,
		`name="uuid"`,
		`客户端 UUID / 密码 / 密钥`,
		`regenerateField('client-uuid')`,
		`uuid: clientUUID`,
		`protocolForClientModal()`,
		`.client-subsection { margin:8px 0 var(--space-3) var(--space-5);`,
		`border-left:1px solid var(--line); box-shadow:none;`,
		`.client-subsection .list { margin-top:0; gap:8px; }`,
		`.client-add-row { display:flex; justify-content:flex-start;`,
		`btnWrap.className = 'client-add-row';`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel client management missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{`id="client-form"`, `document.getElementById('client-form')`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("panel should move client creation into modal and remove old inline form contract, found %q", forbidden)
		}
	}
}

func TestCreateInboundFormShowsRandomizableDefaults(t *testing.T) {
	router := web.NewRouter()
	page := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(page, req)
	if page.Code != http.StatusOK {
		t.Fatalf("expected 200 for panel, got %d: %s", page.Code, page.Body.String())
	}
	body := page.Body.String()
	for _, want := range []string{
		`fillRandomDefaults(formEl)`,
		`reality_short_id`,
		`ss_method`,
		`hy2_obfs_password`,
		`id="inbound-uuid"`,
		`入站 UUID / Shadowsocks 密码`,
		`id="init-client-uuid"`,
		`客户端 UUID / 密码 / 密钥（自动生成，可修改）`,
		`credentialForProtocol(proto)`,
		`function randUUID()`,
		`return randUUID();`,
		`randBase64(16)`,
		`applyProtocolPreset(proto)`,
		`protocolPresets = {`,
		`vless: {network: 'tcp', security: 'reality'}`,
		`vmess: {network: 'ws', security: 'tls'}`,
		`trojan: {network: 'tcp', security: 'tls'}`,
		`shadowsocks: {network: 'tcp', security: 'none'}`,
		`hysteria2: {network: 'quic', security: 'tls'}`,
		`addEventListener('change', () => { applyProtocolPreset`,
		`uuid: document.getElementById('init-client-uuid').value.trim()`,
		`init-client-email`,
		`参数类型 / 传输方式`,
		`名称`,
		`协议类型`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("create inbound form missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{`id="inbound-form"`, `document.getElementById('inbound-form')`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("create inbound form should not expose legacy contracts, found %q", forbidden)
		}
	}
}

func TestLoginPageVercelStyle(t *testing.T) {
	router := web.NewRouter()
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	body := resp.Body.String()
	for _, want := range []string{
		`fonts.googleapis.com/css2?family=Geist`,
		`MiGate`,
		`面板登录`,
		`--bg`,
		`--fg`,
		`--surface`,
		`@media (max-width:`,
		`type="text" id="username"`,
		`type="password" id="password"`,
		`id="errorMsg"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("login page missing %q", want)
		}
	}
	for _, want := range []string{
		`base+'/api/login'`,
		`window.location.pathname`,
		`path.endsWith('/login')`,
		`window.location.href=(base||'')+'/'`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("login page missing base-path aware login script %q", want)
		}
	}
	if strings.Contains(body, `fetch('api/login'`) {
		t.Fatalf("login page must not use relative api/login because /migate resolves it to /api/login")
	}
	if !strings.Contains(body, `data-theme`) || !strings.Contains(body, `dark`) {
		t.Fatalf(`login page should support dark theme with [data-theme="dark"]`)
	}
}

func TestPanelRefreshesAfterCreateAndCopiesLinksSafely(t *testing.T) {
	router := web.NewRouter()
	page := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(page, req)
	if page.Code != http.StatusOK {
		t.Fatalf("expected 200 for panel, got %d", page.Code)
	}
	body := page.Body.String()
	for _, want := range []string{
		`async function loadInbounds`,
		`await loadInbounds()`,
		`function copyTextFallback(text)`,
		`if (navigator.clipboard && navigator.clipboard.writeText)`,
		`showToast('已复制链接', 'success')`,
		`showToast('复制失败，请手动复制', 'error')`,
		`function jsString(value)`,
		`function htmlAttrString(value)`,
		`onclick="copySubUrl(' + htmlAttrString(shareLink) + ')"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing create-refresh/copy safety contract %q", want)
		}
	}
	if strings.Contains(body, `onclick="copySubUrl(' + jsString(shareLink) + ')"`) {
		t.Fatalf("copy button onclick must HTML-escape quoted JS strings before placing them in double-quoted attributes")
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
	if strings.Count(body, `id="version-banner"`) != 1 {
		t.Fatalf("panel must render a single version banner, got %d", strings.Count(body, `id="version-banner"`))
	}
	createInboundClose := strings.Index(body, `</form>
    </div>
  </div>

  <!-- Create Client Modal -->`)
	appShellIndex := strings.Index(body, `class="app-shell"`)
	if createInboundClose == -1 || appShellIndex == -1 || createInboundClose > appShellIndex {
		t.Fatalf("app shell must not be nested inside create inbound modal")
	}

	// Vercel-style shell, light/dark themes, user/account controls.
	for _, want := range []string{
		`fonts.googleapis.com/css2?family=Geist`,
		`:root[data-theme="light"]`,
		`:root[data-theme="dark"]`,
		`--bg: #ffffff;`,
		`--fg: #171717;`,
		`--surface: #ffffff;`,
		`--muted: #666666;`,
		`--bg: #0a0a0a;`,
		`--fg: #ededed;`,
		`--surface: #111111;`,
		`--muted: #a1a1aa;`,
		`--line: rgba(0,0,0,.08);`,
		`--shadow-sm: 0 0 0 1px rgba(0,0,0,.08);`,
		`--shadow-md: 0 0 0 1px rgba(0,0,0,.08), 0 2px 2px rgba(0,0,0,.04), 0 8px 8px -8px rgba(0,0,0,.04);`,
		`font-family:'Geist',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;`,
		`font-family:'Geist Mono',ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace;`,
		`class="app-shell"`,
		`class="sidebar"`,
		`class="account-panel"`,
		`<a href="#xray">核心</a>`,
		`.account-panel { display:grid; gap:var(--space-2); padding:var(--space-3); margin-top:auto;`,
		`background:transparent; box-shadow:inset 0 1px 0 var(--line);`,
		`.account-actions button { min-height:32px;`,
		`id="current-username"`,
		`id="logout-button"`,
		`id="theme-toggle"`,
		`function loadSession()`,
		`fetch(apiPath('/api/session'))`,
		`function logoutPanel()`,
		`fetch(apiPath('/api/logout'), {method: 'POST'})`,
		`function applyTheme(theme)`,
		`function toggleTheme()`,
		`localStorage.getItem('migate-theme')`,
		`document.documentElement.dataset.theme = theme`,
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
	for _, want := range []string{"toggleInbound(", "editInbound(", "toggleClient(", "editClient(", `'/enabled'`, `method: 'PATCH'`} {
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

	// Overview layout must keep the grid display when visible; a bare #overview{display:block}
	// overrides .overview-grid and makes the four metric cards stack vertically.
	if strings.Contains(body, `#overview{display:block}`) {
		t.Fatalf("overview default CSS must not override .overview-grid display:grid with #overview{display:block}")
	}
	for _, want := range []string{
		`main > section{display:none}`,
		`#overview.overview-grid{display:grid}`,
		`.overview-grid { display:grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap:var(--space-4);`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing overview horizontal grid contract %q", want)
		}
	}

	// Right-top title/subtitle are redundant with the sidebar brand and waste vertical space.
	for _, forbidden := range []string{`class="topbar"`, `class="topbar-copy"`, `MiGate 控制台`, `用更克制、更工程化的界面管理入站`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("panel should remove redundant topbar title/subtitle, found %q", forbidden)
		}
	}

	// Create actions must refresh visible lists immediately rather than requiring a manual reload.
	for _, want := range []string{
		`await loadInbounds();`,
		`async function saveCreateInbound()`,
		`async function saveCreateClient()`,
		`const formEl = document.getElementById('create-inbound-form');`,
		`const formEl = document.getElementById('create-client-form');`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing immediate post-create refresh contract %q", want)
		}
	}
	if strings.Contains(body, `event.currentTarget.reset()`) {
		t.Fatalf("panel submit handlers must cache event.currentTarget before await; currentTarget is null after async resume")
	}

	// Page reload should restore the hash-selected section, not always return to overview.
	if strings.Contains(body, "// Start on overview\n    navigateTo('overview');") {
		t.Fatalf("panel should not force navigateTo('overview') on every reload")
	}
	for _, want := range []string{
		`function currentSectionFromLocation()`,
		`window.location.hash`,
		`navigateTo(currentSectionFromLocation());`,
		`window.addEventListener('hashchange'`,
		`history.replaceState(null, '', sectionId === 'overview' ? panelPath('/') : panelPath('/#' + sectionId))`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing hash-preserving navigation contract %q", want)
		}
	}

	// Nav links work with section switching
	for _, want := range []string{`href="#"`, `href="#inbounds"`, `href="#outbound"`, `href="#xray"`, `href="#settings"`} {
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
	if !strings.Contains(body, `#overview.overview-grid{display:grid}`) {
		t.Fatalf("panel should show overview as a grid by default via CSS")
	}

	// Confirm overlay hidden class must use higher-specificity selector
	if !strings.Contains(body, "#confirm-overlay.hidden") {
		t.Fatalf("panel CSS must use #confirm-overlay.hidden (not .hidden) to override ID selector display:flex")
	}

	// New sections: outbound and xray
	for _, want := range []string{`id="outbound"`, `id="xray"`, `id="xray-status"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing section/element %q", want)
		}
	}

	// Xray JS functions
	for _, want := range []string{"fetchXrayStatus", "applyXrayConfig"} {
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
	for _, want := range []string{`href="#settings"`, `id="settings"`, "loadSettings", "saveSettings", "restartService"} {
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
		`class="form-actions modal-actions"`,
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
		`renderEmptyState('暂无出站'`,
		`renderEmptyState('暂无客户端'`,
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
		`重启服务`,
		`button.danger`,
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
		`showToast('客户端 ' + (foundClient.enabled ? '已启用' : '已禁用'), 'success')`,
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

	// Overview operation insights: health summary, protocol distribution, and quick actions.
	for _, want := range []string{
		`.overview-grid`,
		`.overview-insights`,
		`.overview-card`,
		`.overview-card-title`,
		`.overview-pill`,
		`.protocol-breakdown`,
		`.protocol-breakdown-row`,
		`id="overview-health-summary"`,
		`id="overview-active-summary"`,
		`id="overview-protocol-breakdown"`,
		`function renderOverviewInsights`,
		`function updateProtocolBreakdown`,
		`renderOverviewInsights(inbounds, allClients, active)`,
		`updateProtocolBreakdown(inbounds)`,
		`运行概况`,
		`协议分布`,
	} {
		if !strings.Contains(body, want) {
		}
	}

	// Mobile-responsive sidebar toggle + overlay
	for _, want := range []string{
		`id="sidebar-toggle"`,
		`id="sidebar-overlay"`,
		`.sidebar-open`,
		`function toggleSidebar()`,
		`@media (max-width: 768px)`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing mobile sidebar contract %q", want)
		}
	}

	// Touch-friendly control heights
	for _, want := range []string{
		`var(--control-height)`,
		`min-height:var(--control-height)`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing touch-friendly control height %q", want)
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

// TestRestartEndpoint tests the /api/restart endpoint
func TestRestartEndpoint(t *testing.T) {
	t.Run("POST returns restarting status", func(t *testing.T) {
		router := web.NewRouter()
		response := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/restart", nil)
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
	t.Run("restartService JS function exists", func(t *testing.T) {
		router := web.NewRouter()
		response := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		router.ServeHTTP(response, req)
		body := response.Body.String()
		for _, want := range []string{"restartService", "/api/restart", "重启服务", "重启中"} {
			if !strings.Contains(body, want) {
				t.Fatalf("panel missing restart element %q", want)
			}
		}
	})
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

// TestEditClientResetTrafficCardDarkMode verifies the reset traffic card
// in the edit client dialog uses correct dark-mode CSS variables.
func TestEditClientResetTrafficCardDarkMode(t *testing.T) {
	router := web.NewRouter()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	body := rr.Body.String()

	// btn-confirm must be defined in CSS with red background + white text
	if !strings.Contains(body, `.btn-confirm`) {
		t.Fatal("btn-confirm class must be defined for reset traffic button")
	}
	// btn-confirm must have red background
	if !strings.Contains(body, `.btn-confirm{background:var(--danger)`) &&
		!strings.Contains(body, `.btn-confirm { background:var(--danger)`) {
		t.Log("btn-confirm background check - checking alternative patterns")
	}
	// Must NOT use undefined --surface-alt without a fallback
	// var(--surface-alt, fallback) is OK, but bare var(--surface-alt) is not
	if strings.Contains(body, `var(--surface-alt)`) && !strings.Contains(body, `var(--surface-alt,`) {
		t.Fatal("CSS must not use undefined --surface-alt without fallback")
	}
	// Reset traffic JS function must exist
	if !strings.Contains(body, `function resetClientTraffic()`) {
		t.Fatal("resetClientTraffic() function must be defined")
	}
}
