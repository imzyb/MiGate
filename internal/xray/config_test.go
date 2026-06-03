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
		{ID: 4, UUID: "44444444-4444-4444-8444-444444444444", Remark: "ss", Protocol: "shadowsocks", Port: 1080, Network: "tcp", Security: "none", Enabled: true, Clients: []db.Client{{UUID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", Email: "d@example.com", Enabled: true}}},
		{ID: 5, UUID: "55555555-5555-4555-8555-555555555555", Remark: "disabled", Protocol: "vless", Port: 1443, Network: "tcp", Security: "none", Enabled: false, Clients: []db.Client{{UUID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", Email: "disabled@example.com", Enabled: true}}},
	}

	config, err := xray.BuildConfig(inbounds)
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	if len(config.Inbounds) != 4 {
		t.Fatalf("expected four enabled inbounds, got %+v", config.Inbounds)
	}
	if len(config.Outbounds) != 1 || config.Outbounds[0].Protocol != "freedom" {
		t.Fatalf("expected direct freedom outbound, got %+v", config.Outbounds)
	}

	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	text := string(encoded)
	for _, want := range []string{"vless", "vmess", "trojan", "shadowsocks", "a@example.com", "b@example.com", "c@example.com", "d@example.com"} {
		if !strings.Contains(text, want) {
			t.Fatalf("config missing %q: %s", want, text)
		}
	}
	if strings.Contains(text, "disabled@example.com") {
		t.Fatalf("disabled inbound leaked into xray config: %s", text)
	}
}

func TestBuildConfigRejectsUnsupportedProtocol(t *testing.T) {
	_, err := xray.BuildConfig([]db.Inbound{{Protocol: "openvpn", Port: 1194, Enabled: true}})
	if err == nil {
		t.Fatal("expected unsupported protocol error")
	}
}
