package web_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/web"
)

func TestVPNGateEgressCapabilitiesAPIIsReadOnlyPlan(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	before, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list before: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/api/vpngate/egress/capabilities", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}

	var got map[string]interface{}
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse capabilities response: %v", err)
	}
	for key, want := range map[string]interface{}{
		"status":                "planned",
		"driver":                "softether",
		"isolation":             "network_namespace",
		"bridge":                "socks5",
		"performs_side_effects": false,
	} {
		if got[key] != want {
			t.Fatalf("expected %s=%v, got %v in %+v", key, want, got[key], got)
		}
	}
	if got["max_active_default"] != float64(1) {
		t.Fatalf("expected max_active_default=1, got %+v", got["max_active_default"])
	}
	protocols, ok := got["supported_protocols"].([]interface{})
	if !ok || len(protocols) == 0 || protocols[0] != "softether" {
		t.Fatalf("expected supported_protocols to include softether, got %+v", got["supported_protocols"])
	}
	fallbacks, ok := got["fallback_protocols"].([]interface{})
	if !ok || len(fallbacks) == 0 {
		t.Fatalf("expected planned fallback_protocols, got %+v", got["fallback_protocols"])
	}
	if fallback, ok := fallbacks[0].(map[string]interface{}); !ok || fallback["protocol"] != "openvpn" || fallback["status"] != "planned" {
		t.Fatalf("expected planned openvpn fallback, got %+v", got["fallback_protocols"])
	}
	message := fmt.Sprint(got["message"], " ", got["notes"])
	for _, want := range []string{"SoftEther", "network namespace", "SOCKS", "不会直接按 SOCKS5 导入"} {
		if !strings.Contains(message, want) {
			t.Fatalf("capability message missing %q: %s", want, message)
		}
	}

	after, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list after: %v", err)
	}
	if len(after) != len(before) {
		t.Fatalf("capabilities endpoint must not create outbounds: before=%d after=%d", len(before), len(after))
	}
}

func TestCreateVPNGateSoftEtherEgressCreatesPendingBridgeOutbound(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := web.NewRouter(web.WithStore(store))
	payload := `{"server":{"hostname":"vpn123.opengw.net","ip":"203.0.113.10","country_long":"Japan","country_short":"JP"},"bridge_address":"127.0.0.1","bridge_port":21088}`
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/vpngate/egress", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", resp.Code, resp.Body.String())
	}

	var got struct {
		Status   string      `json:"status"`
		Runtime  string      `json:"runtime"`
		Bridge   interface{} `json:"bridge"`
		Notes    []string    `json:"notes"`
		Outbound db.Outbound `json:"outbound"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if got.Status != "pending_runtime" || got.Runtime != "bridge_not_started" {
		t.Fatalf("expected pending runtime status, got %+v body=%s", got, resp.Body.String())
	}
	if got.Outbound.ID == 0 || got.Outbound.Protocol != "vpngate_softether" || !strings.HasPrefix(got.Outbound.Tag, "vpngate-") {
		t.Fatalf("unexpected created outbound: %+v", got.Outbound)
	}
	if got.Outbound.Address != "127.0.0.1" || got.Outbound.Port != 21088 || !got.Outbound.Enabled {
		t.Fatalf("expected local bridge address to be persisted, got %+v", got.Outbound)
	}
	if !strings.Contains(got.Outbound.Remark, "vpn123.opengw.net") || !strings.Contains(got.Outbound.Remark, "Japan") {
		t.Fatalf("expected server identity in remark, got %q", got.Outbound.Remark)
	}
	joinedNotes := strings.Join(got.Notes, " ")
	for _, forbidden := range []string{"connected", "已连接", "started"} {
		if strings.Contains(strings.ToLower(joinedNotes), forbidden) {
			t.Fatalf("response must not claim runtime is started/connected: %+v", got.Notes)
		}
	}

	outbounds, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list outbounds: %v", err)
	}
	found := false
	for _, ob := range outbounds {
		if ob.ID == got.Outbound.ID {
			found = true
			if ob.Protocol != "vpngate_softether" || ob.Address != "127.0.0.1" || ob.Port != 21088 {
				t.Fatalf("stored outbound mismatch: %+v", ob)
			}
		}
	}
	if !found {
		t.Fatalf("created outbound not persisted: %+v", outbounds)
	}
}

func TestCreateVPNGateSoftEtherEgressDefaultsLocalBridgeWithoutRuntimeSideEffects(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := web.NewRouter(web.WithStore(store))
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/vpngate/egress", strings.NewReader(`{"server":{"hostname":"default-port","ip":"198.51.100.2"}}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", resp.Code, resp.Body.String())
	}
	var got struct {
		Status   string `json:"status"`
		Runtime  string `json:"runtime"`
		Outbound struct {
			Protocol string `json:"protocol"`
			Address  string `json:"address"`
			Port     int    `json:"port"`
		} `json:"outbound"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if got.Status != "pending_runtime" || got.Runtime != "bridge_not_started" {
		t.Fatalf("unexpected runtime status: %+v", got)
	}
	if got.Outbound.Protocol != "vpngate_softether" || got.Outbound.Address != "127.0.0.1" || got.Outbound.Port != 21080 {
		t.Fatalf("expected safe default local bridge, got %+v", got.Outbound)
	}
}

func TestOutboundsAPIListsDefaultsAndCreatesOutbound(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	router := web.NewRouter(web.WithStore(store))

	list := httptest.NewRecorder()
	router.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/outbounds", nil))
	if list.Code != http.StatusOK {
		t.Fatalf("expected 200 listing outbounds, got %d: %s", list.Code, list.Body.String())
	}
	for _, want := range []string{`"tag":"direct"`, `"protocol":"freedom"`, `"tag":"blocked"`, `"protocol":"blackhole"`} {
		if !strings.Contains(list.Body.String(), want) {
			t.Fatalf("outbounds list missing %q: %s", want, list.Body.String())
		}
	}

	payload := []byte(`{"tag":"proxy-socks","remark":"SOCKS代理","protocol":"socks","address":"127.0.0.1","port":1080,"username":"sam","password":"secret"}`)
	created := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/outbounds", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(created, req)
	if created.Code != http.StatusCreated {
		t.Fatalf("expected 201 creating outbound, got %d: %s", created.Code, created.Body.String())
	}
	for _, want := range []string{`"tag":"proxy-socks"`, `"protocol":"socks"`, `"address":"127.0.0.1"`, `"port":1080`, `"enabled":true`} {
		if !strings.Contains(created.Body.String(), want) {
			t.Fatalf("create outbound response missing %q: %s", want, created.Body.String())
		}
	}

	outbounds, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list outbounds: %v", err)
	}
	if len(outbounds) != 3 || outbounds[2].Tag != "proxy-socks" {
		t.Fatalf("outbound was not persisted: %+v", outbounds)
	}
}

func TestUpdateOutboundAPIUpdatesFields(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ob, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{
		Tag: "proxy-http", Protocol: "http", Address: "10.0.0.1", Port: 8080,
	})
	if err != nil {
		t.Fatalf("create outbound: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	payload := []byte(`{"tag":"proxy-http-v2","remark":"HTTP代理v2","protocol":"socks","address":"10.0.0.2","port":1080,"username":"newuser","password":"newpass","enabled":false}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/outbounds/"+strconv.FormatInt(ob.ID, 10), bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	for _, want := range []string{`"tag":"proxy-http-v2"`, `"protocol":"socks"`, `"address":"10.0.0.2"`, `"port":1080`, `"enabled":false`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("update response missing %q: %s", want, response.Body.String())
		}
	}

	outbounds, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, o := range outbounds {
		if o.ID == ob.ID {
			if o.Tag != "proxy-http-v2" || o.Enabled != false {
				t.Fatalf("updated values not persisted: %+v", o)
			}
		}
	}
}

func TestUpdateOutboundAPIRejectsUnknownID(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	router := web.NewRouter(web.WithStore(store))
	payload := []byte(`{"tag":"x","remark":"x","protocol":"socks","address":"1.1.1.1","port":80}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/outbounds/99999", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", response.Code, response.Body.String())
	}
}

func TestDeleteOutboundAPIDeletesOutbound(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ob, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{
		Tag: "temp-proxy", Protocol: "socks", Address: "10.0.0.1", Port: 1080,
	})
	if err != nil {
		t.Fatalf("create outbound: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/outbounds/"+strconv.FormatInt(ob.ID, 10), nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}

	outbounds, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, o := range outbounds {
		if o.ID == ob.ID {
			t.Fatalf("outbound %d still present after delete", ob.ID)
		}
	}
}

func TestDeleteOutboundAPIRejectsUnknownID(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/outbounds/99999", nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", response.Code, response.Body.String())
	}
}

func TestRoutingRulesAPICRUD(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	router := web.NewRouter(web.WithStore(store))

	// GET: empty list
	listResp := httptest.NewRecorder()
	router.ServeHTTP(listResp, httptest.NewRequest(http.MethodGet, "/api/routing-rules", nil))
	if listResp.Code != 200 {
		t.Fatalf("expected 200 listing routing rules, got %d: %s", listResp.Code, listResp.Body.String())
	}
	if listResp.Body.String() != "[]\n" && listResp.Body.String() != "null\n" {
		t.Fatalf("expected empty list, got %s", listResp.Body.String())
	}

	// POST: create rule
	payload := `{"inbound_tag":"","outbound_tag":"blocked","domain":"geosite:malware"}`
	createResp := httptest.NewRecorder()
	router.ServeHTTP(createResp, httptest.NewRequest(http.MethodPost, "/api/routing-rules", strings.NewReader(payload)))
	if createResp.Code != 201 {
		t.Fatalf("expected 201 creating routing rule, got %d: %s", createResp.Code, createResp.Body.String())
	}
	var createResult map[string]interface{}
	if err := json.Unmarshal(createResp.Body.Bytes(), &createResult); err != nil {
		t.Fatalf("parse create response: %v", err)
	}
	rule := createResult["rule"].(map[string]interface{})
	if rule["outbound_tag"] != "blocked" || rule["domain"] != "geosite:malware" {
		t.Fatalf("unexpected created rule: %+v", rule)
	}
	id := int(rule["id"].(float64))

	// GET: verify rule in list
	listResp2 := httptest.NewRecorder()
	router.ServeHTTP(listResp2, httptest.NewRequest(http.MethodGet, "/api/routing-rules", nil))
	var rules []interface{}
	if err := json.Unmarshal(listResp2.Body.Bytes(), &rules); err != nil {
		t.Fatalf("parse list: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d: %s", len(rules), listResp2.Body.String())
	}

	// PUT: update rule
	updatePayload := `{"inbound_tag":"socks-in","outbound_tag":"direct","domain":"geosite:netflix","enabled":false}`
	updateResp := httptest.NewRecorder()
	router.ServeHTTP(updateResp, httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/routing-rules/%d", id), strings.NewReader(updatePayload)))
	if updateResp.Code != 200 {
		t.Fatalf("expected 200 updating rule, got %d: %s", updateResp.Code, updateResp.Body.String())
	}

	// DELETE
	deleteResp := httptest.NewRecorder()
	router.ServeHTTP(deleteResp, httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/routing-rules/%d", id), nil))
	if deleteResp.Code != 200 {
		t.Fatalf("expected 200 deleting rule, got %d: %s", deleteResp.Code, deleteResp.Body.String())
	}

	// Verify empty
	listResp3 := httptest.NewRecorder()
	router.ServeHTTP(listResp3, httptest.NewRequest(http.MethodGet, "/api/routing-rules", nil))
	if listResp3.Body.String() != "[]\n" && listResp3.Body.String() != "null\n" {
		t.Fatalf("expected empty after delete, got %s", listResp3.Body.String())
	}

	// DELETE unknown
	deleteUnknown := httptest.NewRecorder()
	router.ServeHTTP(deleteUnknown, httptest.NewRequest(http.MethodDelete, "/api/routing-rules/99999", nil))
	if deleteUnknown.Code != 404 {
		t.Fatalf("expected 404 deleting unknown rule, got %d", deleteUnknown.Code)
	}
}

func TestInboundsAPIListsStoredInboundsWithClients(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark:   "主入口",
		Protocol: "vless",
		Port:     443,
		Network:  "tcp",
		Security: "reality",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	_, err = store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "sam@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/inbounds", nil)
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"remark":"主入口"`, `"protocol":"vless"`, `"port":443`, `"email":"sam@example.com"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "panel_password") || strings.Contains(body, "super-secret-password") {
		t.Fatalf("inbounds api leaked panel secrets: %s", body)
	}
}

func TestCreateInboundAPIStoresInbound(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := web.NewRouter(web.WithStore(store))
	payload := []byte(`{"remark":"新入口","protocol":"trojan","port":9443,"network":"tcp","security":"tls"}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/inbounds", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"remark":"新入口"`, `"protocol":"trojan"`, `"port":9443`, `"enabled":true`} {
		if !strings.Contains(body, want) {
			t.Fatalf("create response missing %q: %s", want, body)
		}
	}

	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(inbounds) != 1 || inbounds[0].Remark != "新入口" || inbounds[0].Protocol != "trojan" {
		t.Fatalf("inbound was not persisted: %+v", inbounds)
	}
}

func TestCreateInboundAPIStoresXHTTPFieldsFromJSON(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := web.NewRouter(web.WithStore(store))
	payload := []byte(`{"remark":"XHTTP入口","protocol":"vless","port":30040,"network":"xhttp","security":"reality","reality_dest":"www.cloudflare.com:443","reality_server_names":"www.cloudflare.com","xhttp_path":"/migate-xhttp","xhttp_mode":"stream-one"}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/inbounds", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"network":"xhttp"`, `"xhttp_path":"/migate-xhttp"`, `"xhttp_mode":"stream-one"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("create response missing %q: %s", want, body)
		}
	}

	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(inbounds) != 1 || inbounds[0].XHTTPPath != "/migate-xhttp" || inbounds[0].XHTTPMode != "stream-one" {
		t.Fatalf("JSON API did not persist xhttp fields: %+v", inbounds)
	}
}

func TestCreateInboundAPIRejectsUnsupportedProtocol(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := web.NewRouter(web.WithStore(store))
	payload := []byte(`{"remark":"legacy","protocol":"openvpn","port":1194,"network":"udp"}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/inbounds", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "unsupported_protocol") {
		t.Fatalf("expected unsupported_protocol body, got: %s", response.Body.String())
	}
	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(inbounds) != 0 {
		t.Fatalf("unsupported inbound should not persist: %+v", inbounds)
	}
}

func TestCreateClientAPIStoresClientUnderInbound(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "vless", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	payload := []byte(`{"email":"client@example.com"}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10)+"/clients", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"email":"client@example.com"`, `"enabled":true`} {
		if !strings.Contains(body, want) {
			t.Fatalf("create client response missing %q: %s", want, body)
		}
	}
	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(inbounds) != 1 || len(inbounds[0].Clients) != 1 || inbounds[0].Clients[0].Email != "client@example.com" {
		t.Fatalf("client was not persisted under inbound: %+v", inbounds)
	}
}

func TestCreateClientAPIRejectsUnknownInbound(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := web.NewRouter(web.WithStore(store))
	payload := []byte(`{"email":"ghost@example.com"}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/inbounds/999/clients", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", response.Code, response.Body.String())
	}
}

func TestXrayConfigAPIProducesPreviewFromStoredInbounds(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "vless", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	_, err = store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "client@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/xray/config", nil)
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"inbounds"`, `"outbounds"`, `"protocol":"vless"`, `"protocol":"freedom"`, `"email":"client@example.com"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("xray config response missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"systemctl", "restart", "write", "openvpn", "egress"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Fatalf("xray config preview leaked side-effect/heavy marker %q: %s", forbidden, body)
		}
	}
}

func TestSubscriptionEndpointReturnsClientShareLink(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "主入口", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "sam@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.UUID, nil)
	req.Host = "panel.example.com"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{"vless://" + client.UUID + "@panel.example.com:443", "type=tcp", "security=reality", "sam%40example.com"} {
		if !strings.Contains(body, want) {
			t.Fatalf("subscription missing %q: %s", want, body)
		}
	}
}

func TestSubscriptionEndpointStripsPanelPortBeforeAppendingInboundPort(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "主入口", Protocol: "vless", Port: 8443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "sam@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.UUID, nil)
	req.Host = "127.0.0.1:9999"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	want := "vless://" + client.UUID + "@127.0.0.1:8443"
	if !strings.Contains(body, want) {
		t.Fatalf("subscription should strip panel port before appending inbound port, want %q got %s", want, body)
	}
	if strings.Contains(body, "127.0.0.1:9999:8443") {
		t.Fatalf("subscription contains double port: %s", body)
	}
}

func TestSubscriptionEndpointRejectsUnknownClient(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/missing", nil)
	router.ServeHTTP(response, req)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", response.Code, response.Body.String())
	}
}

func TestSubscriptionVlessFormat(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "vless-node", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "user1"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.UUID, nil)
	req.Host = "panel.example.com"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	prefix := "vless://" + client.UUID + "@panel.example.com:443?"
	if !strings.HasPrefix(body, prefix) {
		t.Fatalf("vless format mismatch, want prefix %q, got %s", prefix, body)
	}
	if !strings.Contains(body, "type=tcp") {
		t.Fatalf("vless missing type=tcp: %s", body)
	}
	if !strings.Contains(body, "security=reality") {
		t.Fatalf("vless missing security=reality: %s", body)
	}
	if !strings.HasSuffix(body, "#user1") {
		t.Fatalf("vless missing remark fragment: %s", body)
	}
}

func TestSubscriptionVmessReturnsBase64JSON(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "vmess-node", Protocol: "vmess", Port: 8443, Network: "ws", Security: "tls",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "vmess-user"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.UUID, nil)
	req.Host = "panel.example.com"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.HasPrefix(body, "vmess://") {
		t.Fatalf("vmess should start with vmess://, got: %s", body)
	}
	// Decode base64 part
	b64 := body[len("vmess://"):]
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		// Try URL-safe variant
		decoded, err = base64.URLEncoding.DecodeString(b64)
		if err != nil {
			t.Fatalf("vmess link is not valid base64: %s, error: %v", b64, err)
		}
	}
	var vmessData map[string]interface{}
	if err := json.Unmarshal(decoded, &vmessData); err != nil {
		t.Fatalf("vmess decoded data is not valid JSON: %s, error: %v", string(decoded), err)
	}
	for _, want := range []struct{ k, v string }{
		{"v", "2"}, {"ps", "vmess-user"}, {"add", "panel.example.com"},
		{"id", client.UUID}, {"aid", "0"}, {"scy", "auto"},
		{"net", "ws"}, {"tls", "tls"},
	} {
		if got, ok := vmessData[want.k]; !ok || fmt.Sprint(got) != want.v {
			t.Fatalf("vmess JSON field %q expected %q, got %q (value: %v)", want.k, want.v, got, got)
		}
	}
}

func TestSubscriptionTrojanReturnsTrojanLink(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "trojan-node", Protocol: "trojan", Port: 443, Network: "tcp", Security: "tls",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "trojan-user"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.UUID, nil)
	req.Host = "panel.example.com"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	prefix := "trojan://" + client.UUID + "@panel.example.com:443?"
	if !strings.HasPrefix(body, prefix) {
		t.Fatalf("trojan format mismatch, want prefix %q, got %s", prefix, body)
	}
	if !strings.Contains(body, "security=tls") {
		t.Fatalf("trojan missing security=tls: %s", body)
	}
	if !strings.HasSuffix(body, "#trojan-user") {
		t.Fatalf("trojan missing remark fragment: %s", body)
	}
}

func TestSubscriptionShadowsocksReturnsSSLink(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		UUID: "manual-ss-password", Remark: "ss-node", Protocol: "shadowsocks", Port: 8388, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "ss-user"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.UUID, nil)
	req.Host = "panel.example.com"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.HasPrefix(body, "ss://") {
		t.Fatalf("shadowsocks should start with ss://, got: %s", body)
	}
	// Verify base64 encoded method:password@host:port
	after := body[len("ss://"):]
	atIdx := strings.Index(after, "@")
	if atIdx < 0 {
		t.Fatalf("ss:// missing @ sign: %s", body)
	}
	encodedCreds := after[:atIdx]
	decoded, err := base64.StdEncoding.DecodeString(encodedCreds)
	if err != nil {
		decoded, err = base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(encodedCreds)
		if err != nil {
			t.Fatalf("ss:// credentials not valid base64: %s, error: %v", encodedCreds, err)
		}
	}
	creds := string(decoded)
	if !strings.Contains(creds, ":") || !strings.Contains(creds, inbound.UUID) {
		t.Fatalf("ss:// decoded credentials %q should contain method:password with inbound password/key", creds)
	}
	if !strings.HasSuffix(body, "#ss-user") {
		t.Fatalf("ss:// missing remark fragment: %s", body)
	}
}

func TestUpdateInboundAPIUpdatesFields(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "old", Protocol: "vless", Port: 443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	body := `{"remark":"new","port":8443,"network":"ws","security":"tls","enabled":false}`
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10), bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	resp := response.Body.String()
	for _, want := range []string{`"remark":"new"`, `"port":8443`, `"network":"ws"`, `"security":"tls"`, `"enabled":false`} {
		if !strings.Contains(resp, want) {
			t.Fatalf("update response missing %q: %s", want, resp)
		}
	}
}

func TestPatchInboundEnabledAPIPartiallyUpdatesEnabledOnly(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark:             "ws-entry",
		Protocol:           "vless",
		Port:               8443,
		Network:            "ws",
		Security:           "reality",
		WsPath:             "/migate",
		WsHost:             "example.com",
		RealityDest:        "www.cloudflare.com:443",
		RealityServerNames: "www.cloudflare.com",
		RealityShortID:     "abcd1234",
		XHTTPPath:          "/xhttp",
		XHTTPMode:          "stream-one",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10)+"/enabled", bytes.NewReader([]byte(`{"enabled":false}`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	resp := response.Body.String()
	for _, want := range []string{`"remark":"ws-entry"`, `"protocol":"vless"`, `"port":8443`, `"network":"ws"`, `"security":"reality"`, `"ws_path":"/migate"`, `"ws_host":"example.com"`, `"reality_dest":"www.cloudflare.com:443"`, `"xhttp_path":"/xhttp"`, `"xhttp_mode":"stream-one"`, `"enabled":false`} {
		if !strings.Contains(resp, want) {
			t.Fatalf("patch enabled response missing preserved field %q: %s", want, resp)
		}
	}

	loaded, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Enabled || loaded[0].Remark != "ws-entry" || loaded[0].WsPath != "/migate" || loaded[0].XHTTPMode != "stream-one" {
		t.Fatalf("PATCH enabled did not preserve inbound fields: %+v", loaded)
	}
}

func TestPatchClientEnabledAPIPartiallyUpdatesEnabledOnly(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "test", Protocol: "vless", Port: 443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "old@test.com", TrafficLimit: 12345, ExpiryAt: 1893456000})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10)+"/clients/"+strconv.FormatInt(client.ID, 10)+"/enabled", bytes.NewReader([]byte(`{"enabled":false}`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	resp := response.Body.String()
	for _, want := range []string{`"email":"old@test.com"`, `"traffic_limit":12345`, `"expiry_at":1893456000`, `"enabled":false`} {
		if !strings.Contains(resp, want) {
			t.Fatalf("patch client response missing preserved field %q: %s", want, resp)
		}
	}

	loaded, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(loaded) != 1 || len(loaded[0].Clients) != 1 || loaded[0].Clients[0].Enabled || loaded[0].Clients[0].Email != "old@test.com" || loaded[0].Clients[0].TrafficLimit != 12345 {
		t.Fatalf("PATCH enabled did not preserve client fields: %+v", loaded)
	}
}

func TestPatchClientEnabledAPIRejectsClientOutsideInbound(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inboundA, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "a", Protocol: "vless", Port: 443, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound a: %v", err)
	}
	inboundB, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "b", Protocol: "vless", Port: 8443, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound b: %v", err)
	}
	clientB, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inboundB.ID, Email: "b@test.com"})
	if err != nil {
		t.Fatalf("create client b: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/api/inbounds/"+strconv.FormatInt(inboundA.ID, 10)+"/clients/"+strconv.FormatInt(clientB.ID, 10)+"/enabled", bytes.NewReader([]byte(`{"enabled":false}`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for client outside inbound, got %d: %s", response.Code, response.Body.String())
	}
	loaded, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(loaded) != 2 || len(loaded[1].Clients) != 1 || !loaded[1].Clients[0].Enabled {
		t.Fatalf("cross-inbound PATCH changed the wrong client: %+v", loaded)
	}
}

func TestUpdateInboundAPIRejectsUnknownInbound(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := web.NewRouter(web.WithStore(store))
	body := `{"remark":"new","port":8443,"network":"tcp","security":"none","enabled":true}`
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/inbounds/99999", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown inbound, got %d: %s", response.Code, response.Body.String())
	}
}

func TestUpdateClientAPIUpdatesFields(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "test", Protocol: "vless", Port: 443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "old@test.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	body := `{"email":"new@test.com","enabled":false}`
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10)+"/clients/"+strconv.FormatInt(client.ID, 10), bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	resp := response.Body.String()
	for _, want := range []string{`"email":"new@test.com"`, `"enabled":false`} {
		if !strings.Contains(resp, want) {
			t.Fatalf("update client response missing %q: %s", want, resp)
		}
	}
}

func TestUpdateClientAPIRejectsUnknownClient(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := web.NewRouter(web.WithStore(store))
	body := `{"email":"x","enabled":true}`
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/inbounds/1/clients/99999", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown client, got %d: %s", response.Code, response.Body.String())
	}
}

type fakeXrayController struct {
	statusCalls int
	applyCalls  int
}

func (f *fakeXrayController) Status(ctx context.Context) web.XrayStatus {
	f.statusCalls++
	return web.XrayStatus{Service: "xray", Status: "running", Managed: true, CommandsExecuted: []string{}}
}

func (f *fakeXrayController) Apply(ctx context.Context) web.XrayApplyResult {
	f.applyCalls++
	return web.XrayApplyResult{Status: "applied", Service: "xray", CommandsExecuted: []string{"xray -test -config /usr/local/etc/xray/config.json", "systemctl restart xray"}}
}

func (f *fakeXrayController) Version(ctx context.Context) string { return "Xray 1.8.0" }

func TestXrayStatusAPIIsReadOnly(t *testing.T) {
	controller := &fakeXrayController{}
	router := web.NewRouter(web.WithXrayController(controller))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/xray/status", nil)
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"service":"xray"`, `"status":"running"`, `"managed":true`, `"commands_executed":[]`} {
		if !strings.Contains(body, want) {
			t.Fatalf("status response missing %q: %s", want, body)
		}
	}
	if controller.statusCalls != 1 || controller.applyCalls != 0 {
		t.Fatalf("status must be read-only, calls: status=%d apply=%d", controller.statusCalls, controller.applyCalls)
	}
}

func TestXrayApplyAPIRejectsWithoutDoubleConfirmation(t *testing.T) {
	controller := &fakeXrayController{}
	router := web.NewRouter(web.WithXrayController(controller))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/xray/apply", bytes.NewReader([]byte(`{"confirm":true}`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"error":"confirmation_required"`, `"commands_executed":[]`} {
		if !strings.Contains(body, want) {
			t.Fatalf("rejection response missing %q: %s", want, body)
		}
	}
	if controller.applyCalls != 0 {
		t.Fatalf("rejected apply must not call controller, calls=%d", controller.applyCalls)
	}
}

func TestXrayApplyAPICallsControllerAfterDoubleConfirmation(t *testing.T) {
	controller := &fakeXrayController{}
	router := web.NewRouter(web.WithXrayController(controller))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/xray/apply", bytes.NewReader([]byte(`{"confirm":true,"allow_system_changes":true}`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"status":"applied"`, `"service":"xray"`, `"systemctl restart xray"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("apply response missing %q: %s", want, body)
		}
	}
	if controller.applyCalls != 1 || controller.statusCalls != 0 {
		t.Fatalf("apply should call only apply once, calls: status=%d apply=%d", controller.statusCalls, controller.applyCalls)
	}
}

func TestXrayVersionAPIReturnsVersionFromController(t *testing.T) {
	controller := &fakeXrayController{}
	router := web.NewRouter(web.WithXrayController(controller))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/xray/version", nil)
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var data map[string]string
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if data["version"] != "Xray 1.8.0" {
		t.Fatalf("expected version 'Xray 1.8.0', got %q", data["version"])
	}
}

func TestRealControllerWritesConfigAndRunsValidationBeforeRestart(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	_, err = store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "test", Protocol: "vless", Port: 8443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	configDir := t.TempDir()
	var calls []string
	mockRun := func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return "ok", nil
	}

	controller := web.NewRealController(store, configDir, mockRun)
	result := controller.Apply(context.Background())

	if result.Status != "applied" {
		t.Fatalf("expected status 'applied', got %q", result.Status)
	}
	configPath := configDir + "/xray.json"
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("config file was not written: %v", err)
	}
	if !strings.Contains(string(configBytes), `"protocol": "vless"`) {
		t.Fatalf("config missing inbound: %s", string(configBytes))
	}
	if len(calls) < 2 {
		t.Fatalf("expected at least 2 runner calls, got %d: %v", len(calls), calls)
	}
	if !strings.Contains(calls[0], "xray") || !strings.Contains(calls[0], "-test") {
		t.Fatalf("first call should be xray -test, got %q", calls[0])
	}
	if !strings.Contains(calls[len(calls)-1], "systemctl restart xray") {
		t.Fatalf("last call should be systemctl restart, got %q", calls[len(calls)-1])
	}
}

func TestRealControllerApplyStopsOnValidationFailure(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	_, err = store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "test", Protocol: "vmess", Port: 8443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	configDir := t.TempDir()
	var calls []string
	mockRun := func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if len(calls) == 1 {
			return "FAILED", fmt.Errorf("xray validation failed")
		}
		return "ok", nil
	}

	controller := web.NewRealController(store, configDir, mockRun)
	result := controller.Apply(context.Background())

	if len(calls) != 1 {
		t.Fatalf("expected only 1 call (validation), got %d: %v", len(calls), calls)
	}
	if !strings.Contains(result.Status, "failed") {
		t.Fatalf("expected status to indicate failure, got %q", result.Status)
	}
}

func TestDeleteInboundAPIRemovesInboundAndReturns200(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "to-delete", Protocol: "vless", Port: 443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	router := web.NewRouter(web.WithStore(store), web.WithXrayController(&fakeXrayController{}))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10), nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}

	// Verify inbound is gone
	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	for _, ib := range inbounds {
		if ib.ID == inbound.ID {
			t.Fatal("inbound still present after DELETE")
		}
	}
}

func TestDeleteInboundAPIRejectsUnknownID(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/inbounds/99999", nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown inbound, got %d: %s", response.Code, response.Body.String())
	}
}

func TestDeleteClientAPIRemovesClientAndReturns200(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "parent", Protocol: "vmess", Port: 8443, Network: "ws", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{
		InboundID: inbound.ID, Email: "del@test.com",
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10)+"/clients/"+strconv.FormatInt(client.ID, 10), nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}

	// Verify client is gone
	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	for _, ib := range inbounds {
		for _, c := range ib.Clients {
			if c.ID == client.ID {
				t.Fatal("client still present after DELETE")
			}
		}
	}
}

func TestDeleteClientAPIRejectsUnknownClient(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "parent", Protocol: "trojan", Port: 443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10)+"/clients/99999", nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown client, got %d: %s", response.Code, response.Body.String())
	}
}

func TestSubscriptionSkipsExpiredClient(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "test", Protocol: "vless", Port: 8443})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "expired", ExpiryAt: time.Now().Unix() - 3600})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.UUID, nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 for expired client, got %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), "Subscription expired") {
		t.Fatalf("expected 'Subscription expired' message, got: %s", response.Body.String())
	}
}

func TestSubscriptionSkipsDisabledClient(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "test", Protocol: "vless", Port: 8443})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "disabled"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	// Disable the client
	_, err = store.UpdateClient(context.Background(), client.ID, db.UpdateClientParams{Email: "disabled", Enabled: false, TrafficLimit: 0, ExpiryAt: 0})
	if err != nil {
		t.Fatalf("update client: %v", err)
	}
	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.UUID, nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 for disabled client, got %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), "Subscription disabled") {
		t.Fatalf("expected 'Subscription disabled' message, got: %s", response.Body.String())
	}
}

func TestSubscriptionPassesValidClientWithFutureExpiry(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "test", Protocol: "vless", Port: 8443})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "valid", TrafficLimit: 100000, ExpiryAt: time.Now().Unix() + 86400})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.UUID, nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid client with future expiry, got %d", response.Code)
	}
}

func TestCertStatusReturnsEmptyStateWhenNotConfigured(t *testing.T) {
	router := web.NewRouter()
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/cert/status", nil)
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var data map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if data["domain"] != "" {
		t.Fatalf("expected empty domain, got %v", data["domain"])
	}
	if data["issued"] != false {
		t.Fatalf("expected issued=false, got %v", data["issued"])
	}
}

func TestCertStatusReturnsCertInfoWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/panel.json"
	if err := os.WriteFile(configPath, []byte(`{"cert_domain":"example.com","cert_email":"admin@example.com"}`), 0644); err != nil {
		t.Fatalf("write panel.json: %v", err)
	}
	certDir := dir + "/certs/example.com"
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatalf("mkdir cert dir: %v", err)
	}
	if err := os.WriteFile(certDir+"/fullchain.pem", []byte("fake cert"), 0644); err != nil {
		t.Fatalf("write fullchain: %v", err)
	}
	if err := os.WriteFile(certDir+"/privkey.pem", []byte("fake key"), 0644); err != nil {
		t.Fatalf("write privkey: %v", err)
	}

	router := web.NewRouter(web.WithConfigDir(dir))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/cert/status", nil)
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var data map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if data["domain"] != "example.com" {
		t.Fatalf("expected domain 'example.com', got %v", data["domain"])
	}
	if data["issued"] != true {
		t.Fatalf("expected issued=true, got %v", data["issued"])
	}
	if data["cert_path"] == nil || data["cert_path"] == "" {
		t.Fatalf("expected non-empty cert_path, got %v", data["cert_path"])
	}
}

func TestCertIssueValidatesRequiredFields(t *testing.T) {
	router := web.NewRouter()
	// Missing domain
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/cert/issue", strings.NewReader(`{"domain":"","email":"admin@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty domain, got %d: %s", response.Code, response.Body.String())
	}
	// Missing email
	response2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/cert/issue", strings.NewReader(`{"domain":"example.com","email":""}`))
	req2.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response2, req2)
	if response2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty email, got %d: %s", response2.Code, response2.Body.String())
	}
	// Not available (no configDir)
	response3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, "/api/cert/issue", strings.NewReader(`{"domain":"example.com","email":"admin@example.com"}`))
	req3.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response3, req3)
	if response3.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when no configDir, got %d: %s", response3.Code, response3.Body.String())
	}
}

func TestSettingsGetReturnsNotFoundWithoutConfigDir(t *testing.T) {
	router := web.NewRouter()
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected 404 without configDir, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestSettingsGetReturnsPanelConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/panel.json"
	if err := os.WriteFile(configPath, []byte(`{"panel_port":8888,"panel_username":"admin","has_password":true,"xray_config_path":"/usr/local/migate","web_base_path":"/migate"}`), 0644); err != nil {
		t.Fatalf("write panel.json: %v", err)
	}
	router := web.NewRouter(web.WithConfigDir(dir))
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if data["panel_port"] != float64(8888) {
		t.Fatalf("expected panel_port=8888, got %v", data["panel_port"])
	}
	if _, exists := data["panel_password"]; exists {
		t.Fatalf("panel_password should be masked in GET response")
	}
	if data["has_password"] != true {
		t.Fatalf("expected has_password=true, got %v", data["has_password"])
	}
	if data["xray_config_path"] != "/usr/local/migate" {
		t.Fatalf("expected xray_config_path=/usr/local/migate, got %v", data["xray_config_path"])
	}
}

func TestSettingsPutUpdatesPanelConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/panel.json"
	if err := os.WriteFile(configPath, []byte(`{"panel_port":9999,"panel_username":"admin","panel_password":"secret","web_base_path":"/"}`), 0644); err != nil {
		t.Fatalf("write panel.json: %v", err)
	}
	router := web.NewRouter(web.WithConfigDir(dir))
	body := `{"panel_port":7777,"panel_username":"newadmin","panel_password":"newpass","xray_config_path":"/opt/xray","web_base_path":"/panel"}`
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	// Verify file was written
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var saved map[string]interface{}
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if saved["panel_port"] != float64(7777) {
		t.Fatalf("expected panel_port=7777, got %v", saved["panel_port"])
	}
	if saved["panel_username"] != "newadmin" {
		t.Fatalf("expected panel_username=newadmin, got %v", saved["panel_username"])
	}
	if saved["panel_password"] != "newpass" {
		t.Fatalf("expected panel_password=newpass, got %v", saved["panel_password"])
	}
	if saved["xray_config_path"] != "/opt/xray" {
		t.Fatalf("expected xray_config_path=/opt/xray, got %v", saved["xray_config_path"])
	}
}

func TestSettingsPutPreservesPasswordWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/panel.json"
	if err := os.WriteFile(configPath, []byte(`{"panel_port":9999,"panel_username":"admin","panel_password":"secret","database_path":"/db/migate.db","web_base_path":"/"}`), 0644); err != nil {
		t.Fatalf("write panel.json: %v", err)
	}
	router := web.NewRouter(web.WithConfigDir(dir))
	body := `{"panel_port":7777,"panel_username":"admin","panel_password":"","web_base_path":"/"}`
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var saved map[string]interface{}
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if saved["panel_password"] != "secret" {
		t.Fatalf("expected panel_password preserved as 'secret', got %v", saved["panel_password"])
	}
	if saved["database_path"] != "/db/migate.db" {
		t.Fatalf("expected database_path preserved, got %v", saved["database_path"])
	}
}

func TestRestartReturnsRestarting(t *testing.T) {
	router := web.NewRouter()
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/restart", nil)
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if data["status"] != "restarting" {
		t.Fatalf("expected status=restarting, got %v", data["status"])
	}
}

func TestRestartRejectsNonPost(t *testing.T) {
	router := web.NewRouter()
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		resp := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/api/restart", nil)
		router.ServeHTTP(resp, req)
		if resp.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405 for %s, got %d", method, resp.Code)
		}
	}
}

type mockVPNGateFetcher struct {
	servers []web.VPNGateServer
}

func (m *mockVPNGateFetcher) FetchServers() ([]web.VPNGateServer, error) {
	return m.servers, nil
}

func TestVPNGateServersAPI(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	mockFetcher := &mockVPNGateFetcher{
		servers: []web.VPNGateServer{
			{HostName: "server1", IP: "1.2.3.4", Score: 1000, Ping: 10, CountryLong: "Japan", CountryShort: "JP"},
			{HostName: "server2", IP: "5.6.7.8", Score: 2000, Ping: 20, CountryLong: "USA", CountryShort: "US"},
		},
	}
	router := web.NewRouter(web.WithStore(store), web.WithVPNGateFetcher(mockFetcher))
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/vpngate/servers", nil)
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var servers []web.VPNGateServer
	if err := json.Unmarshal(resp.Body.Bytes(), &servers); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}
	if servers[0].HostName != "server1" || servers[0].IP != "1.2.3.4" {
		t.Errorf("unexpected server0: %+v", servers[0])
	}
}

func TestVPNGateImportAPIUnsupported(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	router := web.NewRouter(web.WithStore(store))

	payload := `{"servers":[{"hostname":"s1","ip":"1.2.3.4","country_long":"Japan","ping":10}]}`
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/vpngate/import", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"error":"unsupported_vpngate_import"`) {
		t.Fatalf("unsupported import response missing stable error code: %s", resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `VPN Gate 官方列表不是 SOCKS5 代理源`) {
		t.Fatalf("unsupported import response missing explanatory detail: %s", resp.Body.String())
	}
	listResp := httptest.NewRecorder()
	router.ServeHTTP(listResp, httptest.NewRequest(http.MethodGet, "/api/outbounds", nil))
	if strings.Contains(listResp.Body.String(), `"VPN Gate - Japan"`) || strings.Contains(listResp.Body.String(), `"address":"1.2.3.4"`) {
		t.Fatalf("unsupported VPN Gate import must not create SOCKS outbound: %s", listResp.Body.String())
	}
}

func TestVPNGateImportEmptyIsUnsupported(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	router := web.NewRouter(web.WithStore(store))
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/vpngate/import", strings.NewReader(`{"servers":[]}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"error":"unsupported_vpngate_import"`) {
		t.Fatalf("unsupported import response missing stable error code: %s", resp.Body.String())
	}
}

func TestVPNGateServersRejectsNonGet(t *testing.T) {
	router := web.NewRouter()
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, httptest.NewRequest(method, "/api/vpngate/servers", nil))
		if resp.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405 for %s, got %d", method, resp.Code)
		}
	}
}

func TestVPNGateProbeAPI(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			buf := make([]byte, 3)
			_, _ = io.ReadFull(conn, buf)
			_, _ = conn.Write([]byte{0x05, 0x00})
			_ = conn.Close()
		}
	}()
	host, portText, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, _ := strconv.Atoi(portText)

	router := web.NewRouter()
	payload := fmt.Sprintf(`{"servers":[{"hostname":"ok","ip":%q,"port":%d},{"hostname":"bad","ip":"127.0.0.1","port":1}]}`, host, port)
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/vpngate/probe", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var results []map[string]interface{}
	if err := json.Unmarshal(resp.Body.Bytes(), &results); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(results) != 2 || results[0]["ok"] != true || results[1]["ok"] != false {
		t.Fatalf("unexpected probe results: %+v", results)
	}
	if results[0]["protocol"] != "socks5" {
		t.Fatalf("expected socks5 protocol probe, got %+v", results[0])
	}
}

func TestVPNGateProbeRejectsPlainTCPWithoutSocks5Handshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	host, portText, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, _ := strconv.Atoi(portText)
	router := web.NewRouter()
	payload := fmt.Sprintf(`{"servers":[{"hostname":"tcp-only","ip":%q,"port":%d}]}`, host, port)
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/vpngate/probe", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var results []map[string]interface{}
	if err := json.Unmarshal(resp.Body.Bytes(), &results); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(results) != 1 || results[0]["ok"] != false {
		t.Fatalf("plain TCP listener must not pass as SOCKS5: %+v", results)
	}
}

func TestVPNGateOutboundHealthAPI(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 3)
				_, _ = io.ReadFull(c, buf)
				_, _ = c.Write([]byte{0x05, 0x00})
			}(conn)
		}
	}()
	host, portText, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, _ := strconv.Atoi(portText)
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	okOutbound, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{Tag: "vpngate-ok", Protocol: "socks", Address: host, Port: port})
	if err != nil {
		t.Fatalf("create ok outbound: %v", err)
	}
	_, err = store.CreateOutbound(context.Background(), db.CreateOutboundParams{Tag: "vpngate-disabled", Protocol: "socks", Address: "127.0.0.1", Port: 1})
	if err != nil {
		t.Fatalf("create disabled outbound: %v", err)
	}
	disabledList, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list outbounds: %v", err)
	}
	for _, ob := range disabledList {
		if ob.Tag == "vpngate-disabled" {
			_, err = store.UpdateOutbound(context.Background(), ob.ID, db.UpdateOutboundParams{Tag: ob.Tag, Remark: ob.Remark, Protocol: ob.Protocol, Address: ob.Address, Port: ob.Port, Username: ob.Username, Password: ob.Password, Enabled: false})
			if err != nil {
				t.Fatalf("disable outbound: %v", err)
			}
		}
	}
	_, err = store.CreateOutbound(context.Background(), db.CreateOutboundParams{Tag: "other-socks", Protocol: "socks", Address: "127.0.0.1", Port: 1})
	if err != nil {
		t.Fatalf("create other outbound: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/vpngate/outbounds/health", nil)
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var result struct {
		Results []struct {
			ID        int64  `json:"id"`
			Tag       string `json:"tag"`
			Address   string `json:"address"`
			Port      int    `json:"port"`
			Enabled   bool   `json:"enabled"`
			OK        bool   `json:"ok"`
			LatencyMS int64  `json:"latency_ms"`
			Error     string `json:"error"`
		} `json:"results"`
		Summary struct {
			Total int `json:"total"`
			OK    int `json:"ok"`
			Fail  int `json:"fail"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.Summary.Total != 1 || result.Summary.OK != 1 || result.Summary.Fail != 0 {
		t.Fatalf("unexpected summary: %+v body=%s", result.Summary, resp.Body.String())
	}
	if len(result.Results) != 1 || result.Results[0].ID != okOutbound.ID || result.Results[0].Tag != "vpngate-ok" || !result.Results[0].OK {
		t.Fatalf("unexpected results: %+v", result.Results)
	}
}

func TestVPNGateImportRejectsNonPost(t *testing.T) {
	router := web.NewRouter()
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, httptest.NewRequest(method, "/api/vpngate/import", nil))
		if resp.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405 for %s, got %d", method, resp.Code)
		}
	}
}
