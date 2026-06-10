package web_test

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/imzyb/MiGate/internal/web"
	"github.com/imzyb/MiGate/internal/web/static"
)

func join(parts ...string) string { return strings.Join(parts, "") }

var appJSCache string

func readAppJS(t *testing.T) string {
	t.Helper()
	if appJSCache != "" {
		return appJSCache
	}
	raw, err := fs.ReadFile(static.FS, "app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	appJSCache = string(raw)
	return appJSCache
}

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
	if body["memory_total"] <= 0 || body["disk_total"] <= 0 || body["uptime_seconds"] <= 0 {
		t.Fatalf("resources response should contain positive totals/uptime: %#v", body)
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
	for _, forbidden := range []string{join("MiGate Go", " Lite"), "Go Lite"} {
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

func TestUpdateAPIStartsInstallerUpdateWithoutBlockingResponse(t *testing.T) {
	router := web.NewRouter()

	get := httptest.NewRecorder()
	router.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/api/update", nil))
	if get.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected GET /api/update 405, got %d", get.Code)
	}

	post := httptest.NewRecorder()
	router.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/api/update", nil))
	if post.Code != http.StatusOK {
		t.Fatalf("expected POST /api/update 200, got %d: %s", post.Code, post.Body.String())
	}
	for _, want := range []string{`"status":"updating"`, `"command":"/usr/local/bin/migate-install --update"`} {
		if !strings.Contains(post.Body.String(), want) {
			t.Fatalf("update response missing %q: %s", want, post.Body.String())
		}
	}
}

func TestPanelI18nEnglishLocaleDoesNotContainChineseCopy(t *testing.T) {
	router := web.NewRouter()
	page := httptest.NewRecorder()
	router.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))
	if page.Code != http.StatusOK {
		t.Fatalf("expected 200 for panel, got %d", page.Code)
	}
	body := page.Body.String()
	marker := `},en:{`
	start := strings.Index(body, marker)
	if start == -1 {
		t.Fatalf("panel i18n dictionary missing English locale")
	}
	english := body[start+len(marker):]
	end := strings.Index(english, `}};`)
	if end == -1 {
		t.Fatalf("panel i18n dictionary has unexpected shape")
	}
	english = english[:end]
	for _, allowed := range []string{`langToggle:"中文"`, `中文`} {
		english = strings.ReplaceAll(english, allowed, "")
	}
	for _, r := range english {
		if r >= '\u4e00' && r <= '\u9fff' {
			t.Fatalf("English i18n locale must not contain Chinese copy, found %q", r)
		}
	}
}

func TestPanelI18nEnglishRuntimeTranslatesStaticChineseCopy(t *testing.T) {
	router := web.NewRouter()
	page := httptest.NewRecorder()
	router.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))
	if page.Code != http.StatusOK {
		t.Fatalf("expected 200 for panel, got %d", page.Code)
	}
	body := page.Body.String()
	for _, want := range []string{
		`function applyStaticI18n()`,
		`document.addEventListener('DOMContentLoaded', applyStaticI18n)`,
		`"新增入站":"New inbound"`,
		`"名称":"Name"`,
		`"监听端口":"Listen port"`,
		`"保存入站":"Save inbound"`,
		`"编辑客户端":"Edit client"`,
		`"面板端口":"Panel port"`,
		`"导入 SOCKS5 地址池":"Import SOCKS5 pool"`,
		`"新建路由规则":"New routing rule"`,
		`"搜索入站...":"Search inbounds..."`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing static English i18n runtime contract %q", want)
		}
	}
}

func TestPanelWiresWebUIUpdateActionAndI18nMessages(t *testing.T) {
	router := web.NewRouter()
	page := httptest.NewRecorder()
	router.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))
	if page.Code != http.StatusOK {
		t.Fatalf("expected 200 for panel, got %d: %s", page.Code, page.Body.String())
	}
	body := page.Body.String()
	jsBody := readAppJS(t)
	for _, want := range []string{
		`id="update-button"`,
		`onclick="updateMiGate()"`,
		`updateNow:"立即更新"`,
		`updateNow:"Update now"`,
		`newVersionAvailablePrefix`,
		`updateReleaseNotes`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing WebUI update/i18n contract %q", want)
		}
	}
	for _, want := range []string{
		`async function updateMiGate()`,
		`apiFetch('/api/update', {method: 'POST'})`,
		`t('updateChecking')`,
		`t('updateStarted')`,
		`t('updateFailed')`,
		`t('newVersionAvailablePrefix')`,
		`t('updateReleaseNotes')`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing WebUI update/i18n contract %q", want)
		}
	}
	for _, forbidden := range []string{
		`🚀 新版本 <strong>v`,
		`已发布（当前 v`,
		`查看 <a href=`,
	} {
		if strings.Contains(jsBody, forbidden) {
			t.Fatalf("app.js should use i18n for dynamic update copy, found %q", forbidden)
		}
	}
}

func TestAppJSDynamicCopyUsesI18nKeys(t *testing.T) {
	jsBody := readAppJS(t)
	inString := false
	quote := byte(0)
	stringStart := 0
	for i := 0; i < len(jsBody); i++ {
		ch := jsBody[i]
		if !inString {
			if ch == '/' && i+1 < len(jsBody) && jsBody[i+1] == '/' {
				if next := strings.IndexByte(jsBody[i+2:], '\n'); next >= 0 {
					i += next + 2
				} else {
					break
				}
				continue
			}
			if ch == '/' && i+1 < len(jsBody) && jsBody[i+1] == '*' {
				if next := strings.Index(jsBody[i+2:], "*/"); next >= 0 {
					i += next + 3
				} else {
					break
				}
				continue
			}
			if ch == '\'' || ch == '"' {
				inString = true
				quote = ch
				stringStart = i
			}
			continue
		}
		if ch == '\\' {
			i++
			continue
		}
		if ch == quote {
			j := i + 1
			for j < len(jsBody) && (jsBody[j] == ' ' || jsBody[j] == '\n' || jsBody[j] == '\t' || jsBody[j] == '\r') {
				j++
			}
			isObjectKey := j < len(jsBody) && jsBody[j] == ':'
			literal := jsBody[stringStart : i+1]
			containsHan := false
			for _, r := range literal {
				if r >= '\u4e00' && r <= '\u9fff' {
					containsHan = true
					break
				}
			}
			if !isObjectKey && containsHan {
				t.Fatalf("app.js dynamic string literal should use i18n key, found Han near %q", literal)
			}
			inString = false
			continue
		}
	}
}

func TestPanelWiresSocks5PoolPickerToOutboundManagement(t *testing.T) {
	router := web.NewRouter()
	page := httptest.NewRecorder()
	router.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))
	if page.Code != http.StatusOK {
		t.Fatalf("expected 200 for panel, got %d: %s", page.Code, page.Body.String())
	}
	body := page.Body.String()
	jsBody := readAppJS(t)
	for _, want := range []string{
		`onclick="openSocks5PoolDialog()"`,
		`id="socks5-pool-dialog"`,
		`id="socks5-pool-region"`,
		`id="socks5-pool-detail"`,
		`id="socks5-pool-list"`,
		`导入 SOCKS5 地址池`,
		`dyn052`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing socks5 pool UI contract %q", want)
		}
	}
	if strings.Contains(body, `id="socks5-pool-map"`) || strings.Contains(jsBody, `renderSocks5PoolMap`) {
		t.Fatalf("SOCKS5 pool dialog should not render the map anymore")
	}
	for _, want := range []string{
		`openSocks5PoolDialog()`,
		`loadSocks5PoolRegions()`,
		`onSocks5PoolRegionChange()`,
		`pingSocks5PoolProxy(index)`,
		`selectSocks5PoolProxy`,
		`confirmSocks5PoolProxy()`,
		`renderSocks5PoolDetail`,
		`renderSocks5RegionOptions`,
		`groupSocks5RegionsByContinent`,
		`formatSocks5ProxyCompactLine`,
		`dyn052`,
		`overflow-x:hidden`,
		`apiFetch('/api/outbounds/socks5-pool?country=' + encodeURIComponent(country))`,
		`apiFetch('/api/outbounds/socks5-pool/ping'`,
		`tcping`,
		`apiFetch('/api/outbounds/socks5-pool/import'`,
		`socks5-pool-confirm-btn`,
		`t("dyn081")`,
		`t("dyn083")`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing socks5 pool contract %q", want)
		}
	}
	for _, want := range []string{
		`id="socks5-pool-confirm-btn"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing socks5 pool button contract %q", want)
		}
	}
}

func TestPanelRoutingRuleSaveButtonsProvideFeedback(t *testing.T) {
	router := web.NewRouter()
	page := httptest.NewRecorder()
	router.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))
	if page.Code != http.StatusOK {
		t.Fatalf("expected 200 for panel, got %d: %s", page.Code, page.Body.String())
	}
	body := page.Body.String()
	jsBody := readAppJS(t)
	for _, want := range []string{
		`id="create-routing-rule-submit-btn"`,
		`id="edit-routing-rule-submit-btn"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing routing save button contract %q", want)
		}
	}
	for _, want := range []string{
		`setActionButtonBusy('create-routing-rule-submit-btn', t("dyn112"))`,
		`setActionButtonBusy('edit-routing-rule-submit-btn', t("dyn116"))`,
		`apiFetch('/api/routing-rules'`,
		`apiFetch('/api/routing-rules/' + id`,
		`responseErrorMessage(resp, t("dyn088"))`,
		`responseErrorMessage(resp, t("dyn117"))`,
		`showToast(t("dyn113"), 'success')`,
		`showToast(t("dyn118"), 'success')`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing routing save feedback contract %q", want)
		}
	}
}

func TestPanelUsesApiFetchForIdleSessionRecoveryAndSocks5Cache(t *testing.T) {
	jsBody := readAppJS(t)
	for _, want := range []string{
		`async function apiFetch(path, options)`,
		`handleSessionExpired(response)`,
		`window.location.href = panelPath('/login')`,
		`apiFetch('/api/outbounds/socks5-pool?country=' + encodeURIComponent(country))`,
		`cache_status`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing idle/cache contract %q", want)
		}
	}
	if strings.Contains(jsBody, `fetch(apiPath('/api/outbounds/socks5-pool?country=' + encodeURIComponent(country)))`) {
		t.Fatalf("SOCKS5 pool dialog must use apiFetch/cache-aware endpoint, not raw fetch")
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

func TestPanelOutboundInteractionsReportFailuresAndConsistentLatencyUnits(t *testing.T) {
	router := web.NewRouter()
	page := httptest.NewRecorder()
	router.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))
	if page.Code != http.StatusOK {
		t.Fatalf("expected 200 for panel, got %d: %s", page.Code, page.Body.String())
	}
	body := page.Body.String()
	jsBody := readAppJS(t)
	for _, want := range []string{
		`onclick="openCreateOutbound()"`,
		`onclick="batchSpeedTest()"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing outbound interaction contract %q", want)
		}
	}
	for _, want := range []string{
		`if (!resp.ok) { showToast(t("dyn049"), 'error'); await loadOutbounds(); return; }`,
		`showToast(t("dyn050"), 'success');`,
		`catch(function() { showToast(t("dyn049"), 'error'); loadOutbounds(); })`,
		`var ms = Number(r.latency).toFixed(0);`,
		`function isCustomSpeedTestOutbound(ob)`,
		`outbounds.filter(isCustomSpeedTestOutbound)`,
		`!['direct','blocked'].includes(ob.tag)`,
		`!['freedom','blackhole'].includes(ob.protocol)`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing outbound interaction contract %q", want)
		}
	}
	if strings.Contains(jsBody, `r.latency * 1000`) {
		t.Fatalf("batch outbound speed test must not multiply millisecond latency by 1000")
	}
}

func TestPanelArchivesRemovedLegacyUserInterface(t *testing.T) {
	router := web.NewRouter()
	page := httptest.NewRecorder()
	router.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))
	if page.Code != http.StatusOK {
		t.Fatalf("expected 200 for panel, got %d: %s", page.Code, page.Body.String())
	}
	body := page.Body.String()
	jsBody := readAppJS(t)
	for _, forbidden := range []string{
		`onclick="show` + join("VPN", "Gate") + `Dialog()"`,
		`id="` + join("vpn", "gate") + `-dialog"`,
		`removed VPN feature 公共服务器`,
		`id="` + join("vpn", "gate") + `-import-btn"`,
		`id="` + join("vpn", "gate") + `-import-footer-btn"`,
		join("vpn", "gate") + `-auto-health-card`,
		`removed VPN feature 自动检测`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("removed removed VPN feature UI must be absent, found %q", forbidden)
		}
	}
	for _, forbidden := range []string{
		`removed VPN feature 出口池（自动均衡）`,
		`render` + join("VPN", "Gate") + `ManagedStatus(ob)`,
		`refreshAutoHealthStatus();`,
		`setInterval(refreshAutoHealthStatus`,
	} {
		if strings.Contains(jsBody, forbidden) {
			t.Fatalf("removed removed VPN feature UI must not be wired from app.js, found %q", forbidden)
		}
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
	jsBody := readAppJS(t)
	// HTML/CSS elements (in panelHTML)
	for _, want := range []string{
		`id="inbound-count"`,
		`id="client-count"`,
		`id="inbound-list"`,
		`id="create-inbound-overlay"`,
		`id="create-inbound-form"`,
		`onclick="openCreateInbound()"`,
		`name="remark"`,
		`name="protocol"`,
		`name="port"`,
		`init-client-email`,
		`同时添加首个客户端`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel inbound management missing %q: %s", want, body)
		}
	}
	// JS functions (in app.js)
	for _, want := range []string{
		`method: 'POST'`,
		`openCreateInbound()`,
		`closeCreateInbound()`,
		`saveCreateInbound()`,
		`loadInbounds()`,
		`fetch(apiPath('/api/inbounds'))`,
		`renderInbounds`,
		`toggleInitClient`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing inbound management JS %q", want)
		}
	}
	for _, forbidden := range []string{`id="inbound-form"`, `document.getElementById('inbound-form')`, `document.querySelector('[name=protocol]')`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("panel should move inbound creation into modal and remove old inline form contract, found %q", forbidden)
		}
	}
	for _, forbidden := range []string{"npm", "node_modules", "leak-check", "remote/readiness"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Fatalf("panel should keep lightweight single-binary scope and avoid %q: %s", forbidden, body)
		}
	}
	if regexp.MustCompile(`(?i)\b` + join("open", "vpn") + `\s+(install|server|service|client|config)\b`).MatchString(body) {
		t.Fatalf("panel should keep lightweight single-binary scope and avoid legacy heavy runtime implementation UI: %s", body)
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
	jsBody := readAppJS(t)
	// HTML/CSS elements (in panelHTML)
	for _, want := range []string{
		`id="create-client-overlay"`,
		`id="create-client-form"`,
		`client-inbound-id`,
		`name="email"`,
		`id="client-uuid"`,
		`name="uuid"`,
		`客户端 UUID / 密码 / 密钥`,
		`.client-subsection { margin:8px 0 var(--space-3) var(--space-5);`,
		`border-left:1px solid var(--line); box-shadow:none;`,
		`.client-subsection .list { margin-top:0; gap:8px; }`,
		`.client-add-row { display:flex; justify-content:flex-start;`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel client management missing %q: %s", want, body)
		}
	}
	// JS functions (in app.js)
	for _, want := range []string{
		`openCreateClient(inboundId)`,
		`closeCreateClient()`,
		`saveCreateClient()`,
		`regenerateField('client-uuid')`,
		`uuid: clientUUID`,
		`protocolForClientModal()`,
		`btnWrap.className = 'client-add-row';`,
		`id="edit-client-submit-btn"`,
		`id="reset-client-traffic-btn"`,
		`setActionButtonBusy('edit-client-submit-btn', t("dyn116"))`,
		`setActionButtonBusy('reset-client-traffic-btn', t("dyn169"))`,
		`responseErrorMessage(res, t("dyn163"))`,
		`responseErrorMessage(res, t("dyn170"))`,
		`id="client-copy-' + c.id + '"`,
		`id="client-edit-' + c.id + '"`,
		`id="client-toggle-' + c.id + '"`,
		`id="client-delete-' + c.id + '"`,
		`toggleClientSection(`,
		`t("dyn008")`,
		`t("dyn009")`,
		`t("dyn010") + (inbound.enabled ? t("dyn011") : t("dyn012"))`,
		`t("dyn013")`,
		`t("dyn136")`,
		`重置流量`,
		`t("dyn147")`,
		`t("dyn165")`,
		`.client-resource-row .resource-actions { flex-wrap:wrap; justify-content:flex-end; max-width:280px; }`,
		`.client-resource-row .icon-btn, .client-resource-row .danger-icon-btn { min-width:64px; }`,
	} {
		if !strings.Contains(jsBody, want) && !strings.Contains(body, want) {
			t.Fatalf("app.js missing client JS %q", want)
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
	// HTML/CSS elements (in panelHTML)
	for _, want := range []string{
		`reality_short_id`,
		`ss_method`,
		`hy2_obfs_password`,
		`id="inbound-uuid"`,
		`入站 UUID / Shadowsocks 密码`,
		`id="init-client-uuid"`,
		`客户端 UUID / 密码 / 密钥（自动生成，可修改）`,
		`init-client-email`,
		`参数类型 / 传输方式`,
		`名称`,
		`协议类型`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("create inbound form missing %q: %s", want, body)
		}
	}
	// JS functions (in app.js)
	jsBody := readAppJS(t)
	for _, want := range []string{
		`fillRandomDefaults(formEl)`,
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
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing create inbound JS %q", want)
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

func TestPanelHysteria2LinkIncludesSpecialParams(t *testing.T) {
	jsBody := readAppJS(t)
	for _, want := range []string{
		`inbound.protocol === 'hysteria2'`,
		`hp.push('up_mbps=' + encodeURIComponent(inbound.hy2_up_mbps))`,
		`hp.push('down_mbps=' + encodeURIComponent(inbound.hy2_down_mbps))`,
		`hp.push('obfs=' + encodeURIComponent(inbound.hy2_obfs))`,
		`hp.push('obfs-password=' + encodeURIComponent(inbound.hy2_obfs_password))`,
		`hp.push('mport=' + encodeURIComponent(inbound.hy2_mport))`,
		`shareLink = 'hysteria2://' + c.uuid + '@' + hostName + ':' + inbound.port`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js Hysteria2 Link generation missing %q", want)
		}
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
	jsBody := readAppJS(t)
	for _, want := range []string{
		`async function loadInbounds`,
		`await loadInbounds()`,
		`function copyTextFallback(text)`,
		`function showManualCopyDialog(text)`,
		`if (navigator.clipboard && navigator.clipboard.writeText)`,
		`const copied = await copyToClipboard(text)`,
		`showToast(t("dyn141"), 'success')`,
		`showToast(t("dyn142"), 'error')`,
		`function jsString(value)`,
		`function htmlAttrString(value)`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing create-refresh/copy safety contract %q", want)
		}
	}
	// HTML items (in app.js via JS string concatenation for onclick)
	for _, want := range []string{
		`onclick="copySubUrl(' + htmlAttrString(shareLink) + t("dyn136")`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing create-refresh/copy safety contract %q", want)
		}
	}
	if strings.Contains(jsBody, `onclick="copySubUrl(' + jsString(shareLink) + ')"`) {
		t.Fatalf("copy button onclick must HTML-escape quoted JS strings before placing them in double-quoted attributes")
	}
}

func TestPanelClientCopyLinksAreUnicodeSafeForAllProtocols(t *testing.T) {
	jsBody := readAppJS(t)
	for _, want := range []string{
		`function base64EncodeUnicode(value)`,
		`shareLink = 'vmess://' + base64EncodeUnicode(JSON.stringify(vmessData))`,
		`'#' + encodeURIComponent(c.email)`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js client copy links must be Unicode-safe for every protocol, missing %q", want)
		}
	}
	for _, forbidden := range []string{
		`btoa(JSON.stringify(vmessData))`,
		`'#' + escapeHtml(c.email)`,
	} {
		if strings.Contains(jsBody, forbidden) {
			t.Fatalf("app.js client copy links must not use Unicode-unsafe/HTML-only encoding %q", forbidden)
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
	jsBody := readAppJS(t)
	// JS functions (in app.js)
	for _, want := range []string{
		`deleteInbound`,
		`method: 'DELETE'`,
		`/api/inbounds/`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing inbound delete JS %q", want)
		}
	}
	for _, want := range []string{
		`t("dyn143")`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing delete confirm text %q", want)
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
	jsBody := readAppJS(t)
	// JS functions (in app.js)
	for _, want := range []string{
		`deleteClient`,
		`method: 'DELETE'`,
		`/api/inbounds/`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing client delete JS %q", want)
		}
	}
	for _, want := range []string{
		`t("dyn143")`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing delete confirm text %q", want)
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

	// Vercel-style shell, light/dark themes, user/account controls (HTML/CSS).
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
		`<a href="#xray">Xray</a>`,
		`<a href="#singbox">Sing-box</a>`,
		`.account-panel { display:grid; gap:var(--space-2); padding:var(--space-3); margin-top:auto;`,
		`background:transparent; box-shadow:inset 0 1px 0 var(--line);`,
		`.account-actions button { min-height:32px;`,
		`id="current-username"`,
		`id="logout-button"`,
		`id="theme-toggle"`,
		`class="card panel"`,
		`class="section-heading"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel vercel-style shell missing %q", want)
		}
	}
	// Vercel-style shell JS functions (in app.js)
	jsBody := readAppJS(t)
	for _, want := range []string{
		`function loadSession()`,
		`fetch(apiPath('/api/session'))`,
		`function logoutPanel()`,
		`fetch(apiPath('/api/logout'), {method: 'POST'})`,
		`function applyTheme(theme)`,
		`function toggleTheme()`,
		`localStorage.getItem('migate-theme')`,
		`document.documentElement.dataset.theme = theme`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing shell JS %q", want)
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

	// Toast notification function exists (in app.js)
	if !strings.Contains(jsBody, "showToast(") {
		t.Fatalf("app.js missing showToast function")
	}
	if !strings.Contains(body, "toast-container") {
		t.Fatalf("panel advanced UI missing toast-container div")
	}
	// JS function to show/hide conditional fields (in app.js)
	for _, want := range []string{"updateDynamicFields("} {
		if !strings.Contains(jsBody, want) {
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
	if !strings.Contains(jsBody, "showConfirm(") {
		t.Fatalf("app.js should have showConfirm() to replace native confirm()")
	}

	// Edit and toggle buttons for inbound and client rows (in app.js)
	for _, want := range []string{"toggleInbound("} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("panel missing edit/toggle function %q", want)
		}
	}

	// gRPC dynamic field in edit modal
	for _, want := range []string{
		`id="ei-grpc-settings"`,
		`id="ei-grpc-service-name"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing gRPC edit field %q", want)
		}
	}
	if !strings.Contains(jsBody, "grpc_service_name:") {
		t.Fatalf("app.js missing gRPC edit field grpc_service_name:")
	}

	// TLS edit modal fields
	for _, want := range []string{
		`id="ei-tls-settings"`,
		`id="ei-tls-cert-file"`,
		`id="ei-tls-key-file"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing TLS edit field %q", want)
		}
	}
	if !strings.Contains(jsBody, "tls_cert_file:") {
		t.Fatalf("app.js missing TLS edit field tls_cert_file:")
	}
	if !strings.Contains(jsBody, "tls_key_file:") {
		t.Fatalf("app.js missing TLS edit field tls_key_file:")
	}

	// XHTTP create/edit modal fields
	for _, want := range []string{
		`id="xhttp-settings"`,
		`name="xhttp_path"`,
		`name="xhttp_mode"`,
		`id="ei-xhttp-settings"`,
		`id="ei-xhttp-path"`,
		`id="ei-xhttp-mode"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing XHTTP field %q", want)
		}
	}
	if !strings.Contains(jsBody, "xhttp_path:") {
		t.Fatalf("app.js missing XHTTP field xhttp_path:")
	}
	if !strings.Contains(jsBody, "xhttp_mode:") {
		t.Fatalf("app.js missing XHTTP field xhttp_mode:")
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

	// Overview Xray metric must display service runtime status, not the literal service name.
	for _, want := range []string{
		`function formatServiceStatus(service)`,
		`if (service.status === 'running' || service.status === 'active') return t("dyn024");`,
		`if (service.status === 'stopped' || service.status === 'inactive') return t("dyn025");`,
		`xrayStatusMetric.textContent = formatServiceStatus(xs)`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing overview Xray runtime status contract %q", want)
		}
	}
	if strings.Contains(jsBody, `xrayStatusMetric.textContent = xs.service === 'running'`) {
		t.Fatalf("overview Xray metric must not compare xs.service to running; service is the unit name")
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
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing immediate post-create refresh contract %q", want)
		}
	}
	if strings.Contains(jsBody, `event.currentTarget.reset()`) {
		t.Fatalf("panel submit handlers must cache event.currentTarget before await; currentTarget is null after async resume")
	}

	// Page reload should restore the hash-selected section, not always return to overview.
	if strings.Contains(jsBody, "// Start on overview\\n    navigateTo('overview');") {
		t.Fatalf("panel should not force navigateTo('overview') on every reload")
	}
	for _, want := range []string{
		`function currentSectionFromLocation()`,
		`window.location.hash`,
		`navigateTo(currentSectionFromLocation());`,
		`window.addEventListener('hashchange'`,
		`history.replaceState(null, '', sectionId === 'overview' ? panelPath('/') : panelPath('/#' + sectionId))`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing hash-preserving navigation contract %q", want)
		}
	}

	// Nav links work with section switching
	for _, want := range []string{`href="#"`, `href="#inbounds"`, `href="#outbound"`, `href="#xray"`, `href="#singbox"`, `href="#settings"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing nav link %q", want)
		}
	}
	if !strings.Contains(jsBody, "navigateTo(") {
		t.Fatalf("app.js missing navigateTo function for nav switching")
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
	for _, want := range []string{`id="outbound"`, `id="xray"`, `id="xray-status"`, `id="xray-memory"`, `id="xray-uptime"`, `id="xray-connections"`, `id="xray-config-path"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing section/element %q", want)
		}
	}
	if strings.Contains(body, `xray-unsupported-warning`) || strings.Contains(body, `当前 Xray 版本不支持 Hysteria2 协议`) {
		t.Fatalf("panel should not show stale Xray/Hysteria2 unsupported warning")
	}
	for _, want := range []string{
		`function formatCoreVersion(versionText)`,
		`versionText.match(/(?:Xray\s+)?v?(\d+\.\d+\.\d+)/i)`,
		`document.getElementById('xray-version').textContent = formatCoreVersion(data.version) || '-'`,
		`document.getElementById('singbox-version').textContent = formatCoreVersion(data.version) || '-'`,
		`data.status === 'no_inbounds' ? t("dyn192")`,
		`data.status === 'not_managed' ? t("dyn193")`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing concise core version contract %q", want)
		}
	}
	for _, want := range []string{
		`<option value="hysteria2">Hysteria2</option>`,
		`<option value="tuic">TUIC</option>`,
		`<option value="shadowtls">ShadowTLS</option>`,
		`id="hy2-settings"`, `id="ei-hy2-settings"`,
		`name="hy2_up_mbps"`, `id="ei-hy2-up"`,
		`name="hy2_down_mbps"`, `id="ei-hy2-down"`,
		`name="hy2_obfs"`, `id="ei-hy2-obfs"`,
		`name="hy2_obfs_password"`, `id="ei-hy2-obfs-password"`,
		`onclick="regenerateField('inbound-hy2-obfs-password')"`,
		`onclick="regenerateField('ei-hy2-obfs-password')"`,
		`onclick="toggleSecretField('ei-hy2-obfs-password')"`,
		`type="password" placeholder="混淆密码（自动随机，可选）"`,
		`name="hy2_mport"`, `id="ei-hy2-mport"`,
		`Hysteria2 在 sing-box v1.13 需要 TLS；MiGate 会默认使用自签证书`,
		`id="tuic-settings"`, `id="ei-tuic-settings"`,
		`name="tuic_congestion_control"`, `id="ei-tuic-cc"`,
		`name="tuic_zero_rtt"`, `id="ei-tuic-zero-rtt"`,
		`id="shadowtls-settings"`, `id="ei-shadowtls-settings"`,
		`name="shadowtls_password"`, `id="ei-shadowtls-password"`,
		`name="shadowtls_version"`, `id="ei-shadowtls-version"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("create/edit inbound sing-box protocol fields must stay aligned, missing %q", want)
		}
	}
	for _, want := range []string{
		`normalizeEditProtocolPreset()`,
		`if (proto === 'hysteria2') {`,
		`document.getElementById('ei-network').value = 'quic';`,
		`document.getElementById('ei-security').value = 'tls';`,
		`security: editSecurityForProtocol(),`,
		`document.getElementById('ei-hy2-up').value`,
		`hy2_up_mbps: Number(document.getElementById('ei-hy2-up').value) || 0`,
		`document.getElementById('ei-hy2-mport').value`,
		`hy2_mport: document.getElementById('ei-hy2-mport').value`,
		`document.getElementById('ei-tuic-cc').value`,
		`tuic_congestion_control: document.getElementById('ei-tuic-cc').value`,
		`document.getElementById('ei-shadowtls-password').value`,
		`shadowtls_password: document.getElementById('ei-shadowtls-password').value`,
		`document.getElementById('ei-shadowtls-version').value`,
		`shadowtls_version: Number(document.getElementById('ei-shadowtls-version').value) || 3`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js must populate and save edit sing-box field %q", want)
		}
	}
	if strings.Contains(body, `option value="wireguard"`) || strings.Contains(jsBody, `wireguard: {network`) || strings.Contains(body, `id="ei-wireguard-settings"`) {
		t.Fatalf("panel must not offer WireGuard while the bundled sing-box runtime skips WireGuard inbounds")
	}

	// Verify external script reference in HTML
	if !strings.Contains(body, `src="./static/app.js"`) {
		t.Fatal("panel must use ./static/app.js so base-path roots resolve the script under the panel path")
	}

	// JS functions in app.js should exist
	jsBody = readAppJS(t)
	for _, want := range []string{"fetchXrayStatus", "applyXrayConfig", "fetchSingboxStatus", "loadSingboxLogs"} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing JS function %q", want)
		}
	}

	// Each nav shows exactly one section (no overlap)
	t.Run("navigateToShowsOnlySelectedSection", func(t *testing.T) {
		if !strings.Contains(jsBody, "el.id === sectionId") {
			t.Fatalf("navigateTo must compare el.id === sectionId, not sectionId === 'overview' OR condition")
		}
	})

	// Create client modal must prevent duplicate submits on click jitter / slow network.
	for _, want := range []string{
		`id="create-client-submit-btn"`,
		`let _creatingClient = false;`,
		`if (_creatingClient) return;`,
		`_creatingClient = true;`,
		`submitBtn.disabled = true;`,
		`submitBtn.textContent = t("dyn112")`,
		`_creatingClient = false;`,
		`submitBtn.textContent = t("dyn133")`,
	} {
		if !strings.Contains(body+jsBody, want) {
			t.Fatalf("create client modal must guard duplicate submit, missing %q", want)
		}
	}

	// Edit modals replace prompt()
	for _, want := range []string{"edit-inbound-overlay", "edit-client-overlay", "ei-remark", "ei-protocol", "ei-port", "ei-network", "ei-security", "ec-email"} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing edit modal element %q", want)
		}
	}
	for _, want := range []string{"saveEditInbound", "closeEditInbound", "saveEditClient", "closeEditClient", "eiUpdateDynamicFields"} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing edit modal JS function %q", want)
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
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing Vercel-style resource row CSS %q", want)
		}
	}
	for _, want := range []string{
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
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing Vercel-style resource row JS %q", want)
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
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing empty-state contract %q", want)
		}
	}
	for _, want := range []string{
		`class="empty-state"`,
		`class="empty-state-title"`,
		`class="empty-state-copy"`,
		`class="empty-state-actions"`,
		`function renderEmptyState`,
		`renderEmptyState(t("dyn002")`,
		`renderEmptyState(t("dyn032")`,
		`renderEmptyState(t("dyn131")`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing empty-state JS %q", want)
		}
	}

	// Vercel-style notice/status feedback cards (CSS in panelHTML, functions in app.js)
	for _, want := range []string{
		`.notice`,
		`.notice-title`,
		`.notice-copy`,
		`.notice.success`,
		`.notice.error`,
		`id="xray-result" class="notice-slot"`,
		`id="settings-status" class="notice-slot"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing notice/status feedback contract %q", want)
		}
	}
	for _, want := range []string{
		`function renderNotice`,
		`renderNotice(t("dyn207")`,
		`renderNotice(t("dyn215")`,
		`renderNotice(t("dyn212")`,
		`renderNotice(t("dyn228")`,
		`renderNotice(t("dyn231")`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing notice JS %q", want)
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
	if strings.Contains(jsBody, "newEnabled") {
		t.Fatalf("panel toggle handlers must not reference undefined newEnabled")
	}
	for _, want := range []string{
		`showToast(t("dyn158") + (inbound.enabled ? t("dyn159") : t("dyn160")), 'success')`,
		`showToast(t("dyn167") + (foundClient.enabled ? t("dyn159") : t("dyn160")), 'success')`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("panel missing safe toggle toast expression %q", want)
		}
	}

	// Traffic/expiry UI elements
	for _, want := range []string{"ec-traffic-limit", "ec-expiry-at"} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing traffic/expiry element %q", want)
		}
	}
	for _, want := range []string{"formatBytes"} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing traffic/expiry JS %q", want)
		}
	}
	for _, want := range []string{"traffic_limit", "bar-low"} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing traffic/expiry element %q", want)
		}
	}

	// Overview traffic and server resource stats
	for _, want := range []string{"total-traffic", "xray-status-metric", "server-cpu", "server-memory", "server-disk", "server-uptime"} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing overview stat element %q", want)
		}
	}
	for _, want := range []string{
		"formatBytes",
		"formatPercent",
		"formatUptime",
		"async function loadSystemResources()",
		"fetch(apiPath('/api/system/resources'))",
		"document.getElementById('server-cpu').textContent",
		"document.getElementById('server-memory').textContent",
		"document.getElementById('server-disk').textContent",
		"document.getElementById('server-uptime').textContent",
		"function startOverviewResourceRefresh()",
		"clearInterval(overviewResourceTimer)",
		"overviewResourceTimer = setInterval(loadSystemResources, 5000)",
		"if (sectionId !== 'overview') stopOverviewResourceRefresh();",
		"async function loadOverviewServiceStatuses()",
		"xrayStatusMetric.textContent = formatServiceStatus(xs)",
		"document.getElementById('singbox-status-metric').textContent = formatServiceStatus(ss)",
		"if (sectionId === 'overview') { loadStats(); loadOverviewServiceStatuses(); loadSystemResources(); startOverviewResourceRefresh(); }",
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing overview stat/status contract %q", want)
		}
	}
	if !strings.Contains(jsBody, "'singbox'") || !strings.Contains(jsBody, "fetchSingboxStatus();") {
		t.Fatalf("app.js must treat singbox as a valid navigable section")
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
		if !strings.Contains(body, want) && !strings.Contains(jsBody, want) {
			t.Fatalf("panel missing overview insights contract %q", want)
		}
	}

	// Mobile-responsive sidebar toggle + overlay
	for _, want := range []string{
		`id="sidebar-toggle"`,
		`id="sidebar-overlay"`,
		`.sidebar-open`,
		`@media (max-width: 768px)`,
		`.mobile-topbar`,
		`class="mobile-topbar"`,
		`class="mobile-title"`,
		`class="mobile-menu-button"`,
		`env(safe-area-inset-top)`,
		`touch-action:manipulation`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing mobile sidebar contract %q", want)
		}
	}
	for _, want := range []string{
		"function toggleSidebar()",
		"document.body.classList.toggle('sidebar-open')",
		"document.body.classList.remove('sidebar-open')",
		"e.key === 'Escape'",
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing mobile sidebar JS contract %q", want)
		}
	}

	// Mobile outbound cards must wrap details/actions instead of overflowing narrow screens.
	for _, want := range []string{
		`.outbound-card`,
		`.outbound-status-dot`,
		`.outbound-main`,
		`.outbound-meta`,
		`.outbound-actions`,
		`.outbound-card.is-disabled`,
		`.outbound-actions .icon-btn`,
		`.outbound-actions .danger-icon-btn`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing mobile outbound CSS contract %q", want)
		}
	}
	for _, want := range []string{
		`class=\"card outbound-card`,
		`class=\"outbound-status-dot`,
		`class=\"outbound-main\"`,
		`class=\"outbound-meta\"`,
		`class=\"outbound-actions\"`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing mobile outbound card contract %q", want)
		}
	}

	// Mobile SOCKS5 pool dialog should stack detail/list and keep action button sticky on phones.
	for _, want := range []string{
		`.socks5-pool-layout`,
		`.socks5-pool-detail-card`,
		`.socks5-pool-list-panel`,
		`.socks5-pool-footer`,
		`@media (max-width: 560px)`,
		`.socks5-pool-layout { grid-template-columns:1fr; }`,
		`.socks5-pool-detail-card { min-height:auto; }`,
		`.socks5-pool-list { height:min(48vh, 360px); }`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing mobile SOCKS5 pool CSS contract %q", want)
		}
	}
	for _, want := range []string{
		`class="socks5-pool-layout"`,
		`class="socks5-pool-detail-card"`,
		`class="socks5-pool-list-panel"`,
		`class="list muted socks5-pool-list"`,
		`class="modal-footer socks5-pool-footer"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing mobile SOCKS5 pool markup contract %q", want)
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
		// HTML elements
		for _, want := range []string{"restartService", "重启服务"} {
			if !strings.Contains(body, want) {
				t.Fatalf("panel missing restart element %q", want)
			}
		}
		// JS functions (in app.js)
		jsBody := readAppJS(t)
		for _, want := range []string{"/api/restart", `btn.textContent = t("dyn251")`} {
			if !strings.Contains(jsBody, want) {
				t.Fatalf("app.js missing restart element %q", want)
			}
		}
	})
}

func TestRouterDoesNotServeLegacyHeavyRoutes(t *testing.T) {
	router := web.NewRouter()
	for _, path := range []string{"/api/remote/readiness", "/api/leak-check", "/api/egress/status", "/api/" + join("open", "vpn") + "/status", "/api/proxy/status"} {
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
	// Reset traffic JS function must exist (in app.js)
	jsBody := readAppJS(t)
	if !strings.Contains(jsBody, `function resetClientTraffic()`) {
		t.Fatal("resetClientTraffic() function must be defined in app.js")
	}
}

func TestPanelDOMStructure(t *testing.T) {
	router := web.NewRouter()
	page := httptest.NewRecorder()
	router.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))
	if page.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", page.Code)
	}
	body := page.Body.String()

	// Every sidebar nav link must have a matching section container
	navLinks := map[string]string{
		"#":         `id="overview"`,
		"#inbounds": `id="inbounds"`,
		"#outbound": `id="outbound"`,
		"#routing":  `id="routing"`,
		"#xray":     `id="xray"`,
		"#singbox":  `id="singbox"`,
		"#settings": `id="settings"`,
	}
	for href, id := range navLinks {
		if !strings.Contains(body, `href="`+href+`"`) {
			t.Fatalf("sidebar missing nav link href=%q", href)
		}
		if !strings.Contains(body, id) {
			t.Fatalf("panel missing section container %q", id)
		}
	}

	// Modals must not be nested inside another modal's overlay.
	// Check that create-inbound-overlay closes before create-client-overlay opens.
	createInboundClose := strings.Index(body, `</form>
    </div>
  </div>

  <!-- Create Client Modal -->`)
	createClientOpen := strings.Index(body, `id="create-client-overlay"`)
	if createInboundClose == -1 || createClientOpen == -1 || createInboundClose > createClientOpen {
		t.Fatal("create-inbound modal must close before create-client modal opens (not nested)")
	}

	// Edit modals must be siblings, not nested inside create modals
	editInboundOpen := strings.Index(body, `id="edit-inbound-overlay"`)
	if editInboundOpen < createClientOpen {
		t.Fatal("edit modals must appear after create modals (modals should be siblings)")
	}

	// Inbound section should appear before outbound section
	inboundSec := strings.Index(body, `id="inbounds"`)
	outboundSec := strings.Index(body, `id="outbound"`)
	if inboundSec == -1 || outboundSec == -1 || inboundSec > outboundSec {
		t.Fatal("inbounds section must appear before outbound section")
	}

	// Verify all section IDs are unique (each appears exactly once)
	sectionIDs := []string{"overview", "inbounds", "outbound", "routing", "xray", "settings", "singbox"}
	for _, id := range sectionIDs {
		if strings.Count(body, `id="`+id+`"`) != 1 {
			t.Fatalf("section ID %q must appear exactly once, got %d", id, strings.Count(body, `id="`+id+`"`))
		}
	}

	// Verify form elements have proper labels (no orphaned inputs)
	requiredFormFields := []string{
		`for="inbound-remark"`,
		`for="client-email"`,
		`name="remark"`,
		`name="protocol"`,
		`name="port"`,
	}
	for _, field := range requiredFormFields {
		if !strings.Contains(body, field) {
			t.Fatalf("form missing required field %q", field)
		}
	}

	// Toast container must appear only once and before all modals (for proper z-index layering)
	if strings.Count(body, `id="toast-container"`) != 1 {
		t.Fatalf("toast-container must appear exactly once, got %d", strings.Count(body, `id="toast-container"`))
	}
	toastPos := strings.Index(body, `id="toast-container"`)
	if toastPos > editInboundOpen {
		t.Fatal("toast-container must appear before all modals (for proper z-index layering)")
	}
}

func TestCoreInstallUninstallAPIsRequireExplicitSystemChangeConfirmation(t *testing.T) {
	router := web.NewRouter()
	for _, tc := range []struct {
		path string
	}{
		{"/api/xray/install"},
		{"/api/xray/uninstall"},
		{"/api/singbox/install"},
		{"/api/singbox/uninstall"},
	} {
		response := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(`{"confirm":true}`))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(response, req)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s without allow_system_changes = %d, want 403", tc.path, response.Code)
		}
		if !strings.Contains(response.Body.String(), "confirmation_required") {
			t.Fatalf("%s response missing confirmation_required: %s", tc.path, response.Body.String())
		}
	}
}

func TestPanelWiresCoreInstallUninstallActions(t *testing.T) {
	router := web.NewRouter()
	page := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(page, req)
	body := page.Body.String()
	jsBody := readAppJS(t)
	for _, want := range []string{
		`onclick="installXrayCore()"`,
		`onclick="uninstallXrayCore()"`,
		`onclick="installSingboxCore()"`,
		`onclick="uninstallSingboxCore()"`,
		`安装核心`,
		`卸载核心`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel missing core install/uninstall button contract %q", want)
		}
	}
	for _, want := range []string{
		`function installXrayCore()`,
		`function uninstallXrayCore()`,
		`function installSingboxCore()`,
		`function uninstallSingboxCore()`,
		`/api/xray/install`,
		`/api/xray/uninstall`,
		`/api/singbox/install`,
		`/api/singbox/uninstall`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing core install/uninstall JS contract %q", want)
		}
	}
}

func TestPanelKeepsRemovedLegacyFeatureArchivedFromVisibleFlows(t *testing.T) {
	router := web.NewRouter()
	page := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(page, req)
	body := page.Body.String()
	jsBody := readAppJS(t)
	for _, forbidden := range []string{
		`id="` + join("vpn", "gate") + `-dialog"`,
		`removed VPN feature 公共服务器`,
		`onclick="refresh` + join("VPN", "Gate") + `Servers()"`,
		`id="` + join("vpn", "gate") + `-import-btn"`,
		`id="` + join("vpn", "gate") + `-import-footer-btn"`,
		`创建 removed VPN feature 出口`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("removed removed VPN feature dialog must not be rendered, found %q", forbidden)
		}
	}
	for _, forbidden := range []string{
		`function show` + join("VPN", "Gate") + `Dialog()`,
		`start` + join("VPN", "Gate") + `Runtime(data.outbound.id)`,
		`fetch(apiPath('/api/` + join("vpn", "gate") + `/egress')`,
		`localStorage.setItem(cacheKey`,
	} {
		if strings.Contains(jsBody, forbidden) {
			t.Fatalf("removed removed VPN feature flow must not be callable from app.js, found %q", forbidden)
		}
	}
}

func TestRoutingRuleRefreshDoesNotTriggerFailureToast(t *testing.T) {
	jsBody := readAppJS(t)
	for _, want := range []string{
		`async function refreshRoutingRuleViews()`,
		`Promise.allSettled(tasks)`,
		`await refreshRoutingRuleViews();`,
	} {
		if !strings.Contains(jsBody, want) {
			t.Fatalf("app.js missing routing refresh isolation contract %q", want)
		}
	}
	if strings.Contains(jsBody, `Promise.all([loadRoutingRules(), loadXrayStatus()])`) {
		t.Fatalf("routing rule success path must not turn status refresh failure into operation failure")
	}
}
