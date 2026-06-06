package xray_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/xray"
)

func TestBuildConfigIncludesSupportedProtocolInboundsAndFreedomOutbound(t *testing.T) {
	inbounds := []db.Inbound{
		{ID: 1, UUID: "11111111-1111-4111-8111-111111111111", Remark: "vless-reality", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality", Enabled: true, Clients: []db.Client{{UUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Email: "a@example.com", Enabled: true}}},
		{ID: 2, UUID: "22222222-2222-4222-8222-222222222222", Remark: "vmess-ws", Protocol: "vmess", Port: 8443, Network: "ws", Security: "tls", Enabled: true, Clients: []db.Client{{UUID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Email: "b@example.com", Enabled: true}}},
		{ID: 3, UUID: "33333333-3333-4333-8333-333333333333", Remark: "trojan", Protocol: "trojan", Port: 9443, Network: "tcp", Security: "tls", Enabled: true, Clients: []db.Client{{UUID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Email: "c@example.com", Enabled: true}}},
		{ID: 4, UUID: "manual-ss-password", Remark: "ss", Protocol: "shadowsocks", Port: 1080, Network: "tcp", Security: "none", Enabled: true, Clients: []db.Client{{UUID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", Email: "d@example.com", Enabled: true}}},
		{ID: 5, UUID: "55555555-5555-4555-8555-555555555555", Remark: "disabled", Protocol: "vless", Port: 1443, Network: "tcp", Security: "none", Enabled: false, Clients: []db.Client{{UUID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", Email: "disabled@example.com", Enabled: true}}},
		{ID: 6, UUID: "66666666-6666-4666-8666-666666666666", Remark: "trojan-reality", Protocol: "trojan", Port: 30030, Network: "tcp", Security: "reality", RealityDest: "www.microsoft.com:443", RealityServerNames: "www.microsoft.com", RealityShortID: "", RealityPrivateKey: "uNisYErm5wwrV9t9EP2P3VB0g3CpS5m70bdG7gwShXg", Enabled: true, Clients: []db.Client{{UUID: "ffffffff-ffff-4fff-8fff-ffffffffffff", Email: "trojan-reality@test.com", Enabled: true}}},
	}

	config, err := xray.BuildConfig(inbounds)
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	if len(config.Inbounds) != 5 {
		t.Fatalf("expected five enabled inbounds, got %+v", config.Inbounds)
	}
	if len(config.Outbounds) != 1 || config.Outbounds[0].Protocol != "freedom" {
		t.Fatalf("expected direct freedom outbound, got %+v", config.Outbounds)
	}

	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	text := string(encoded)
	for _, want := range []string{"vless", "vmess", "trojan", "shadowsocks", "a@example.com", "b@example.com", "c@example.com", "trojan-reality@test.com", "trojan-reality"} {
		if !strings.Contains(text, want) {
			t.Fatalf("config missing %q: %s", want, text)
		}
	}
	if strings.Contains(text, "disabled@example.com") {
		t.Fatalf("disabled inbound leaked into xray config: %s", text)
	}
	// Shadowsocks should use single-user mode (method + password, no clients array)
	if strings.Contains(text, "\"clients\"") && strings.Contains(text, "\"shadowsocks\"") {
		// Check that the clients block is NOT inside the SS inbound
		// Split by inbound tags and check the SS section
		if strings.Index(text, "inbound-4") < strings.Index(text, "inbound-5") {
			ssSection := text[strings.Index(text, "inbound-4"):strings.Index(text, "inbound-5")]
			if strings.Contains(ssSection, "\"clients\"") {
				t.Fatalf("Shadowsocks config should not contain clients array: %s", ssSection)
			}
		}
	}
	// Verify Trojan+REALITY has realitySettings with privateKey and shortIds
	if !strings.Contains(text, "uNisYErm5wwrV9t9EP2P3VB0g3CpS5m70bdG7gwShXg") {
		t.Fatalf("Trojan+REALITY config missing privateKey: %s", text)
	}
	if !strings.Contains(text, "realitySettings") {
		t.Fatalf("Trojan+REALITY config missing realitySettings: %s", text)
	}
	if !strings.Contains(text, "shortIds") {
		t.Fatalf("Trojan+REALITY config missing shortIds: %s", text)
	}
	if !strings.Contains(text, "manual-ss-password") {
		t.Fatalf("Shadowsocks config should preserve user-visible password/key: %s", text)
	}
	if !strings.Contains(text, "password") {
		t.Fatalf("Trojan+REALITY config missing password field: %s", text)
	}
}

func TestBuildConfigWithOutboundsUsesStoredOutbounds(t *testing.T) {
	config, err := xray.BuildConfigWithOutbounds(nil, []db.Outbound{
		{Tag: "direct", Protocol: "freedom", Enabled: true, Sort: 0},
		{Tag: "blocked", Protocol: "blackhole", Enabled: true, Sort: 1},
		{Tag: "proxy-socks", Protocol: "socks", Address: "127.0.0.1", Port: 1080, Username: "sam", Password: "secret", Enabled: true, Sort: 2},
		{Tag: "disabled-proxy", Protocol: "http", Address: "127.0.0.1", Port: 8080, Enabled: false, Sort: 3},
	})
	if err != nil {
		t.Fatalf("build config with outbounds: %v", err)
	}
	if len(config.Outbounds) != 3 {
		t.Fatalf("expected three enabled outbounds, got %+v", config.Outbounds)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	text := string(encoded)
	for _, want := range []string{`"tag":"direct"`, `"protocol":"freedom"`, `"tag":"blocked"`, `"protocol":"blackhole"`, `"tag":"proxy-socks"`, `"protocol":"socks"`, `"address":"127.0.0.1"`, `"port":1080`, `"user":"sam"`, `"pass":"secret"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("outbound config missing %q: %s", want, text)
		}
	}
	if strings.Contains(text, "disabled-proxy") {
		t.Fatalf("disabled outbound leaked into config: %s", text)
	}
}
func TestBuildConfigRejectsUnsupportedProtocol(t *testing.T) {
	_, err := xray.BuildConfig([]db.Inbound{{Protocol: "openvpn", Port: 1194, Enabled: true}})
	if err == nil {
		t.Fatal("expected unsupported protocol error")
	}
}

func TestBuildConfigIncludesXHTTPSettingsForVLESSReality(t *testing.T) {
	config, err := xray.BuildConfig([]db.Inbound{{
		ID:                 7,
		UUID:               "77777777-7777-4777-8777-777777777777",
		Remark:             "vless-xhttp-reality",
		Protocol:           "vless",
		Port:               30040,
		Network:            "xhttp",
		Security:           "reality",
		RealityDest:        "www.cloudflare.com:443",
		RealityServerNames: "www.cloudflare.com",
		RealityPrivateKey:  "uNisYErm5wwrV9t9EP2P3VB0g3CpS5m70bdG7gwShXg",
		XHTTPPath:          "/migate-xhttp",
		XHTTPMode:          "stream-one",
		Enabled:            true,
		Clients:            []db.Client{{UUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Email: "xhttp@test.com", Enabled: true}},
	}})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	text := string(encoded)
	for _, want := range []string{`"network":"xhttp"`, `"xhttpSettings"`, `"path":"/migate-xhttp"`, `"mode":"stream-one"`, `"realitySettings"`, `"shortIds"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("XHTTP config missing %q: %s", want, text)
		}
	}
}

func TestBuildConfigVLESSRealityHasFlowInClients(t *testing.T) {
	inbounds := []db.Inbound{
		{
			ID: 9, UUID: "99999999-9999-4999-8999-999999999999",
			Remark: "vless-tcp-reality-flow", Protocol: "vless", Port: 30110,
			Network: "tcp", Security: "reality",
			RealityDest:        "www.cloudflare.com:443",
			RealityServerNames: "www.cloudflare.com",
			RealityPrivateKey:  "uNisYErm5wwrV9t9EP2P3VB0g3CpS5m70bdG7gwShXg",
			Enabled:            true,
			Clients:            []db.Client{{UUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Email: "flow-test@test.com", Enabled: true}},
		},
		{
			ID: 10, UUID: "10101010-1010-4010-8010-101010101010",
			Remark: "vless-xhttp-reality-flow", Protocol: "vless", Port: 30120,
			Network: "xhttp", Security: "reality",
			XHTTPPath:          "/migate",
			XHTTPMode:          "stream-one",
			RealityDest:        "www.cloudflare.com:443",
			RealityServerNames: "www.cloudflare.com",
			RealityPrivateKey:  "uNisYErm5wwrV9t9EP2P3VB0g3CpS5m70bdG7gwShXg",
			Enabled:            true,
			Clients:            []db.Client{{UUID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Email: "xhttp-flow@test.com", Enabled: true}},
		},
	}
	config, err := xray.BuildConfig(inbounds)
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	encoded, _ := json.Marshal(config)
	text := string(encoded)
	for _, want := range []string{`"flow":"xtls-rprx-vision"`, `"network":"xhttp"`, `"network":"tcp"`, `xhttpSettings`, `realitySettings`} {
		if !strings.Contains(text, want) {
			t.Fatalf("VLESS+REALITY config missing %q: %s", want, text)
		}
	}
	// Verify non-REALITY inbounds don't get flow
	if strings.Contains(text, `"flow":"`) && !strings.Contains(text, `"flow":"xtls-rprx-vision"`) {
		t.Fatalf("unexpected flow value in config: %s", text)
	}
}

func TestBuildConfigGeneratesMissingRealityPrivateKey(t *testing.T) {
	inbounds := []db.Inbound{
		{
			ID: 8, UUID: "88888888-8888-4888-8888-888888888888",
			Remark: "auto-key-reality", Protocol: "vless", Port: 30050,
			Network: "tcp", Security: "reality",
			RealityDest: "www.example.com:443", RealityServerNames: "www.example.com",
			Enabled: true,
			Clients: []db.Client{{UUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Email: "auto-key@test.com", Enabled: true}},
		},
	}
	config, err := xray.BuildConfig(inbounds)
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	if len(config.Inbounds) != 1 {
		t.Fatalf("expected 1 inbound, got %d", len(config.Inbounds))
	}
	encoded, _ := json.Marshal(config)
	text := string(encoded)
	if !strings.Contains(text, "realitySettings") {
		t.Fatalf("auto-key inbound missing realitySettings: %s", text)
	}
	if !strings.Contains(text, "privateKey") {
		t.Fatalf("auto-key inbound missing auto-generated privateKey: %s", text)
	}
}

func TestBuildConfigHysteria2WithTLSUsesCorrectSettings(t *testing.T) {
	config, err := xray.BuildConfig([]db.Inbound{{
		ID:          11,
		UUID:        "11111111-1111-4111-8111-111111111111",
		Remark:      "hy2-tls",
		Protocol:    "hysteria2",
		Port:        43001,
		Network:     "quic",
		Security:    "tls",
		Hy2UpMbps:   50,
		Hy2DownMbps: 100,
		TLSCertFile: "/etc/cert.pem",
		TLSKeyFile:  "/etc/key.pem",
		Enabled:     true,
		Clients:     []db.Client{{UUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Email: "hy2-tls@test.com", Enabled: true}},
	}})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	if len(config.Inbounds) != 1 {
		t.Fatalf("expected 1 inbound, got %d", len(config.Inbounds))
	}
	encoded, _ := json.Marshal(config)
	text := string(encoded)
	for _, want := range []string{`"protocol":"hysteria2"`, `"password":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"`, `"up_mbps":50`, `"down_mbps":100`, `"security":"tls"`, `"tlsSettings"`, `"certificateFile":"/etc/cert.pem"`, `"keyFile":"/etc/key.pem"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("Hysteria2+TLS config missing %q: %s", want, text)
		}
	}
}

func TestBuildConfigHysteria2NoTLSUsesPasswordAuthOnly(t *testing.T) {
	config, err := xray.BuildConfig([]db.Inbound{{
		ID:       12,
		UUID:     "22222222-2222-4222-8222-222222222222",
		Remark:   "hy2-notls",
		Protocol: "hysteria2",
		Port:     43002,
		Network:  "quic",
		Security: "none",
		Enabled:  true,
		Clients:  []db.Client{{UUID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Email: "hy2-notls@test.com", Enabled: true}},
	}})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	if len(config.Inbounds) != 1 {
		t.Fatalf("expected 1 inbound, got %d", len(config.Inbounds))
	}
	encoded, _ := json.Marshal(config)
	text := string(encoded)
	for _, want := range []string{`"protocol":"hysteria2"`, `"password":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"`, `"security":"none"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("Hysteria2+noTLS config missing %q: %s", want, text)
		}
	}
	if strings.Contains(text, "tlsSettings") {
		t.Fatalf("Hysteria2+noTLS should not have tlsSettings: %s", text)
	}
}

func TestBuildConfigHysteria2WithObfsIncludesObfuscationSettings(t *testing.T) {
	config, err := xray.BuildConfig([]db.Inbound{{
		ID:              13,
		UUID:            "33333333-3333-4333-8333-333333333333",
		Remark:          "hy2-obfs",
		Protocol:        "hysteria2",
		Port:            43003,
		Network:         "quic",
		Security:        "tls",
		Hy2UpMbps:       30,
		Hy2DownMbps:     50,
		Hy2Obfs:         "salamander",
		Hy2ObfsPassword: "my-obfs-key",
		TLSCertFile:     "/etc/cert.pem",
		TLSKeyFile:      "/etc/key.pem",
		Enabled:         true,
		Clients:         []db.Client{{UUID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Email: "hy2-obfs@test.com", Enabled: true}},
	}})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	encoded, _ := json.Marshal(config)
	text := string(encoded)
	for _, want := range []string{`"obfs":"salamander"`, `"obfs_password":"my-obfs-key"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("Hysteria2+obfs config missing %q: %s", want, text)
		}
	}
}
