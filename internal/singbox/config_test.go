package singbox

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/imzyb/MiGate/internal/db"
)

func TestBuildConfig_Hysteria2Inbound(t *testing.T) {
	inbounds := []db.Inbound{
		{
			ID: 1, Protocol: "hysteria2", Port: 40002, Enabled: true,
			Hy2UpMbps: 100, Hy2DownMbps: 50,
			Hy2Obfs: "salamander", Hy2ObfsPassword: "obfs-pass",
			Clients: []db.Client{
				{ID: 1, UUID: "client-pass-1", StatsKey: "c_hy2_stats", Email: "user1@test", Enabled: true},
			},
		},
	}

	cfg := BuildConfigWithOptions(inbounds, BuildOptions{EnableV2RayAPIStats: true})

	if len(cfg.Inbounds) != 1 {
		t.Fatalf("expected 1 inbound, got %d", len(cfg.Inbounds))
	}
	ib := cfg.Inbounds[0]
	if ib.Type != "hysteria2" {
		t.Errorf("expected type hysteria2, got %s", ib.Type)
	}
	if ib.ListenPort != 40002 {
		t.Errorf("expected user-facing inbound port 40002, got %d", ib.ListenPort)
	}
	if ib.UpMbps != 100 {
		t.Errorf("expected up_mbps 100, got %d", ib.UpMbps)
	}
	if ib.DownMbps != 50 {
		t.Errorf("expected down_mbps 50, got %d", ib.DownMbps)
	}
	if ib.TLS == nil || !ib.TLS.Enabled {
		t.Fatal("expected Hysteria2 to include generated TLS config required by sing-box")
	}
	if ib.TLS.CertificatePath != CertFile || ib.TLS.KeyPath != KeyFile {
		t.Fatalf("expected default generated TLS certs, got cert=%q key=%q", ib.TLS.CertificatePath, ib.TLS.KeyPath)
	}
	if ib.Obfs == nil || ib.Obfs.Type != "salamander" {
		t.Errorf("expected obfs salamander, got %v", ib.Obfs)
	}
	if ib.Obfs.Password != "obfs-pass" {
		t.Errorf("expected obfs password obfs-pass, got %s", ib.Obfs.Password)
	}
	if len(ib.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(ib.Users))
	}
	if ib.Users[0].Password != "client-pass-1" {
		t.Errorf("expected password client-pass-1, got %s", ib.Users[0].Password)
	}
	if ib.Users[0].Name != "c_hy2_stats" {
		t.Fatalf("expected stats_key user name, got %q", ib.Users[0].Name)
	}
	if cfg.Experimental == nil || cfg.Experimental.V2RayAPI == nil || cfg.Experimental.V2RayAPI.Stats == nil || !cfg.Experimental.V2RayAPI.Stats.Enabled {
		t.Fatal("expected sing-box experimental v2ray stats API to be enabled")
	}
	if len(cfg.Experimental.V2RayAPI.Stats.Inbounds) != 1 || cfg.Experimental.V2RayAPI.Stats.Inbounds[0] != "hy2-inbound-1" {
		t.Fatalf("expected inbound stats list, got %+v", cfg.Experimental.V2RayAPI.Stats.Inbounds)
	}
	if len(cfg.Experimental.V2RayAPI.Stats.Users) != 1 || cfg.Experimental.V2RayAPI.Stats.Users[0] != "c_hy2_stats" {
		t.Fatalf("expected user stats list with stats_key, got %+v", cfg.Experimental.V2RayAPI.Stats.Users)
	}
}

func TestBuildConfig_SerializesV2RayAPIStatsSchema(t *testing.T) {
	inbounds := []db.Inbound{
		{
			ID: 1, Protocol: "hysteria2", Port: 40002, Enabled: true,
			Clients: []db.Client{
				{ID: 1, UUID: "client-pass-1", StatsKey: "c_hy2_stats", Email: "user1@test", Enabled: true},
				{ID: 2, UUID: "disabled-pass", StatsKey: "disabled_stats", Email: "user2@test", Enabled: false},
			},
		},
		{
			ID: 2, Protocol: "tuic", Port: 40003, Enabled: true,
			Clients: []db.Client{{ID: 3, UUID: "tuic-pass", Email: "tuic@test", Enabled: true}},
		},
		{
			ID: 3, Protocol: "shadowtls", Port: 40004, Enabled: true,
			Clients: []db.Client{{ID: 4, UUID: "shadow-pass", StatsKey: "c_shadow", Email: "shadow@test", Enabled: true}},
		},
	}

	raw, err := json.Marshal(BuildConfigWithOptions(inbounds, BuildOptions{EnableV2RayAPIStats: true}))
	if err != nil {
		t.Fatalf("marshal sing-box config: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode sing-box config json: %v", err)
	}
	experimental, ok := decoded["experimental"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected experimental object: %s", raw)
	}
	api, ok := experimental["v2ray_api"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected experimental.v2ray_api object: %s", raw)
	}
	if api["listen"] != "127.0.0.1:10086" {
		t.Fatalf("unexpected v2ray_api listen: %#v", api["listen"])
	}
	stats, ok := api["stats"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected v2ray_api.stats object: %s", raw)
	}
	if stats["enabled"] != true {
		t.Fatalf("expected stats.enabled=true, got %#v", stats["enabled"])
	}
	assertJSONStrings(t, stats["inbounds"], []string{"hy2-inbound-1", "tuic-inbound-2", "shadowtls-inbound-3"})
	assertJSONStrings(t, stats["users"], []string{"c_hy2_stats", "tuic@test", "c_shadow"})
}

func TestBuildConfig_TUICUsesCredentialIDAndPassword(t *testing.T) {
	cfg := BuildConfig([]db.Inbound{{
		ID: 2, Protocol: "tuic", Port: 40003, Enabled: true,
		TuicCongestionControl: "cubic",
		TuicZeroRTT:           true,
		Clients: []db.Client{{
			ID: 7, UUID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", CredentialID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Password: "tuic-secret", Email: "tuic@test", Enabled: true,
		}},
	}})
	if len(cfg.Inbounds) != 1 {
		t.Fatalf("expected 1 inbound, got %+v", cfg.Inbounds)
	}
	ib := cfg.Inbounds[0]
	if ib.Type != "tuic" || ib.CongestionControl != "cubic" || !ib.ZeroRTTHandshake {
		t.Fatalf("unexpected tuic inbound: %+v", ib)
	}
	if len(ib.Users) != 1 || ib.Users[0].UUID != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" || ib.Users[0].Password != "tuic-secret" {
		t.Fatalf("tuic user must use credential_id + password, got %+v", ib.Users)
	}
}

func TestBuildConfig_OmitsV2RayAPIStatsByDefault(t *testing.T) {
	inbounds := []db.Inbound{{
		ID: 1, Protocol: "hysteria2", Port: 40002, Enabled: true,
		Clients: []db.Client{{ID: 1, UUID: "client-pass-1", StatsKey: "c_hy2_stats", Email: "user1@test", Enabled: true}},
	}}

	raw, err := json.Marshal(BuildConfig(inbounds))
	if err != nil {
		t.Fatalf("marshal sing-box config: %v", err)
	}
	if strings.Contains(string(raw), "v2ray_api") {
		t.Fatalf("default config must not include experimental.v2ray_api: %s", raw)
	}
}

func TestBuildConfig_Hysteria2TLSEnabledOnlyWhenRequested(t *testing.T) {
	inbounds := []db.Inbound{
		{
			ID: 1, Protocol: "hysteria2", Port: 21001, Enabled: true,
			Security: "tls", TLSSNI: "example.com",
			Clients: []db.Client{{ID: 1, UUID: "client-pass-1", Enabled: true}},
		},
	}

	cfg := BuildConfig(inbounds)
	if len(cfg.Inbounds) != 1 {
		t.Fatalf("expected 1 inbound, got %d", len(cfg.Inbounds))
	}
	ib := cfg.Inbounds[0]
	if ib.TLS == nil || !ib.TLS.Enabled {
		t.Fatal("expected TLS enabled when Hysteria2 security is tls")
	}
	if ib.TLS.ServerName != "example.com" {
		t.Fatalf("expected TLS server_name from inbound SNI, got %q", ib.TLS.ServerName)
	}
}

func TestBuildConfig_Hysteria2TLSCustomFilesFallBackWhenMissing(t *testing.T) {
	inbounds := []db.Inbound{
		{
			ID: 1, Protocol: "hysteria2", Port: 21001, Enabled: true,
			Security: "tls", TLSCertFile: "/missing/fullchain.pem", TLSKeyFile: "/missing/privkey.pem",
		},
	}

	cfg := BuildConfig(inbounds)
	if len(cfg.Inbounds) != 1 {
		t.Fatalf("expected 1 inbound, got %d", len(cfg.Inbounds))
	}
	ib := cfg.Inbounds[0]
	if ib.TLS == nil || !ib.TLS.Enabled {
		t.Fatal("expected TLS enabled")
	}
	if ib.TLS.CertificatePath != CertFile || ib.TLS.KeyPath != KeyFile {
		t.Fatalf("expected missing custom TLS files to fall back to self-signed cert, got cert=%q key=%q", ib.TLS.CertificatePath, ib.TLS.KeyPath)
	}
}

func TestBuildConfig_DisabledInboundSkipped(t *testing.T) {
	inbounds := []db.Inbound{
		{ID: 1, Protocol: "hysteria2", Port: 21001, Enabled: false},
		{ID: 2, Protocol: "hysteria2", Port: 21002, Enabled: true,
			Clients: []db.Client{{ID: 1, UUID: "p1", Enabled: true}}},
	}

	cfg := BuildConfig(inbounds)
	if len(cfg.Inbounds) != 1 {
		t.Errorf("expected 1 inbound (disabled skipped), got %d", len(cfg.Inbounds))
	}
}

func TestBuildConfig_NonHy2Skipped(t *testing.T) {
	inbounds := []db.Inbound{
		{ID: 1, Protocol: "vless", Port: 10001, Enabled: true,
			Clients: []db.Client{{ID: 1, UUID: "u1", Enabled: true}}},
		{ID: 2, Protocol: "hysteria2", Port: 21001, Enabled: true,
			Clients: []db.Client{{ID: 2, UUID: "p2", Enabled: true}}},
	}

	cfg := BuildConfig(inbounds)
	if len(cfg.Inbounds) != 1 {
		t.Errorf("expected 1 inbound (vless skipped), got %d", len(cfg.Inbounds))
	}
	if cfg.Inbounds[0].Type != "hysteria2" {
		t.Errorf("expected hysteria2, got %s", cfg.Inbounds[0].Type)
	}
}

func TestBuildConfig_HasDirectOutbound(t *testing.T) {
	cfg := BuildConfig(nil)
	found := false
	for _, o := range cfg.Outbounds {
		if o.Type == "direct" && o.Tag == "direct" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected direct outbound with tag direct")
	}
}

func TestBuildConfigWithOutboundsUsesSupportedProfilesAndGeneratedTags(t *testing.T) {
	cfg, err := BuildConfigWithOutbounds(nil, []db.Outbound{
		{ID: 10, Tag: "socks-shared", Protocol: "socks", Address: "127.0.0.1", Port: 1080, Enabled: true},
		{ID: 11, Tag: "vless-shared", Protocol: "vless", Address: "127.0.0.1", Port: 443, Username: "11111111-1111-4111-8111-111111111111", Enabled: true},
		{ID: 12, Tag: "hy2-sb", Protocol: "hysteria2", Address: "127.0.0.1", Port: 8443, Password: "secret", Enabled: true},
	}, []db.RoutingRule{
		{ID: 1, OutboundID: 10, OutboundTag: "socks-shared", Domain: "example.com", Enabled: true},
	})
	if err != nil {
		t.Fatalf("build config with outbounds: %v", err)
	}
	raw, _ := json.Marshal(cfg)
	text := string(raw)
	for _, want := range []string{`"tag":"singbox-out-10"`, `"type":"socks"`, `"tag":"singbox-out-11"`, `"type":"vless"`, `"tag":"singbox-out-12"`, `"type":"hysteria2"`, `"outbound":"singbox-out-10"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("sing-box config missing %q: %s", want, text)
		}
	}
}

func TestBuildConfigWithOutboundsInjectsManagementDirectBeforeUserCatchAll(t *testing.T) {
	cfg, err := BuildConfigWithOutboundsOptions([]db.Inbound{{
		ID: 8, Remark: "hy2-in", Protocol: "hysteria2", Port: 21001, Network: "udp", Security: "tls", Enabled: true,
		Clients: []db.Client{{Email: "user@example.com", UUID: "client-pass", Enabled: true}},
	}}, []db.Outbound{
		{ID: 10, Tag: "proxy", Protocol: "socks", Address: "127.0.0.1", Port: 1080, Enabled: true},
	}, []db.RoutingRule{
		{ID: 1, OutboundID: 10, OutboundTag: "proxy", Domain: "geosite:geolocation-!cn", Enabled: true},
	}, BuildOptions{ManagementDirect: ManagementDirectOptions{
		Enabled: true,
		Hosts:   []string{"103.193.149.217", "HTTP://Panel.Example.COM:9999/panel/", "[2001:db8::1]", "panel.example.com", ""},
		Ports:   []int{9999, 22, 9999, 0, 70000},
	}})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	if cfg.Route == nil || len(cfg.Route.Rules) < 3 {
		t.Fatalf("expected management and user rules, got %+v", cfg.Route)
	}
	ipRule := cfg.Route.Rules[0]
	if ipRule.Outbound != SystemDirectOutboundTag || strings.Join(ipRule.IPCIDR, ",") != "103.193.149.217/32,2001:db8::1/128" || len(ipRule.Port) != 2 || ipRule.Port[0] != 22 || ipRule.Port[1] != 9999 || len(ipRule.Domain) != 0 {
		t.Fatalf("expected management IP rule first, got %+v", ipRule)
	}
	for _, port := range ipRule.Port {
		if port == 80 || port == 443 {
			t.Fatalf("management direct rule must not include common service ports by default, got %+v", ipRule)
		}
	}
	domainRule := cfg.Route.Rules[1]
	if domainRule.Outbound != SystemDirectOutboundTag || strings.Join(domainRule.Domain, ",") != "panel.example.com" || len(domainRule.Port) != 2 || domainRule.Port[0] != 22 || domainRule.Port[1] != 9999 || len(domainRule.IPCIDR) != 0 {
		t.Fatalf("expected management domain rule before user rules, got %+v", domainRule)
	}
	userRule := cfg.Route.Rules[2]
	if userRule.Outbound != "singbox-out-10" || strings.Join(userRule.Domain, ",") != "geosite:geolocation-!cn" || len(userRule.Port) != 0 {
		t.Fatalf("user catch-all should remain routed to proxy outbound, got %+v", userRule)
	}
	found := false
	for _, outbound := range cfg.Outbounds {
		if outbound.Tag == SystemDirectOutboundTag && outbound.Type == "direct" {
			found = true
		}
	}
	if !found {
		t.Fatalf("system direct outbound missing: %+v", cfg.Outbounds)
	}
	for _, rule := range cfg.Route.Rules {
		if rule.Outbound == SystemDirectOutboundTag && len(rule.Port) == 0 {
			t.Fatalf("management direct must not be emitted as a global direct rule: %+v", rule)
		}
	}
}

func TestBuildConfigWithOutboundsKeepsOrdinaryCatchAllOnProxy(t *testing.T) {
	cfg, err := BuildConfigWithOutboundsOptions([]db.Inbound{{
		ID: 8, Remark: "hy2-in", Protocol: "hysteria2", Port: 21001, Network: "udp", Security: "tls", Enabled: true,
		Clients: []db.Client{{Email: "user@example.com", UUID: "client-pass", Enabled: true}},
	}}, []db.Outbound{
		{ID: 10, Tag: "socks-proxy", Protocol: "socks", Address: "127.0.0.1", Port: 1081, Enabled: true},
	}, []db.RoutingRule{
		{ID: 1, OutboundID: 10, OutboundTag: "socks-proxy", Enabled: true},
	}, BuildOptions{ManagementDirect: ManagementDirectOptions{
		Enabled: true,
		Hosts:   []string{"panel.example.com"},
		Ports:   []int{9999},
	}})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	if cfg.Route == nil {
		t.Fatal("expected route config")
	}
	var userRules []RouteRule
	for _, rule := range cfg.Route.Rules {
		if rule.Outbound != SystemDirectOutboundTag {
			userRules = append(userRules, rule)
			continue
		}
		if len(rule.Port) != 1 || rule.Port[0] != 9999 || strings.Join(rule.Domain, ",") != "panel.example.com" {
			t.Fatalf("management direct must only match management host+port, got %+v", rule)
		}
	}
	if len(userRules) != 1 || userRules[0].Outbound != "singbox-out-10" || len(userRules[0].Domain) != 0 || len(userRules[0].IPCIDR) != 0 || len(userRules[0].Port) != 0 {
		t.Fatalf("ordinary catch-all should remain routed to proxy outbound, got %+v", userRules)
	}
}

func TestBuildConfigWithOutboundsPreservesStatsAPIWithManagementDirect(t *testing.T) {
	cfg, err := BuildConfigWithOutboundsOptions([]db.Inbound{{
		ID: 1, Protocol: "hysteria2", Port: 40002, Enabled: true,
		Clients: []db.Client{{ID: 1, UUID: "client-pass-1", StatsKey: "c_hy2_stats", Email: "user1@test", Enabled: true}},
	}}, []db.Outbound{
		{ID: 10, Tag: "proxy", Protocol: "socks", Address: "127.0.0.1", Port: 1080, Enabled: true},
	}, []db.RoutingRule{
		{ID: 1, OutboundID: 10, OutboundTag: "proxy", Domain: "geosite:geolocation-!cn", Enabled: true},
	}, BuildOptions{
		EnableV2RayAPIStats: true,
		ManagementDirect: ManagementDirectOptions{
			Enabled: true,
			Hosts:   []string{"103.193.149.217"},
			Ports:   []int{9999},
		},
	})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	if cfg.Experimental == nil || cfg.Experimental.V2RayAPI == nil || cfg.Experimental.V2RayAPI.Stats == nil || !cfg.Experimental.V2RayAPI.Stats.Enabled {
		t.Fatalf("expected stats API to remain enabled, got %+v", cfg.Experimental)
	}
	if len(cfg.Route.Rules) == 0 || cfg.Route.Rules[0].Outbound != SystemDirectOutboundTag {
		t.Fatalf("expected management direct route to remain first, got %+v", cfg.Route)
	}
}

func TestBuildConfigWithOutboundsSkipsManagementDirectWhenDisabled(t *testing.T) {
	cfg, err := BuildConfigWithOutboundsOptions(nil, []db.Outbound{
		{ID: 10, Tag: "proxy", Protocol: "socks", Address: "127.0.0.1", Port: 1080, Enabled: true},
	}, []db.RoutingRule{
		{ID: 1, OutboundID: 10, OutboundTag: "proxy", Domain: "geosite:geolocation-!cn", Enabled: true},
	}, BuildOptions{ManagementDirect: ManagementDirectOptions{
		Enabled: false,
		Hosts:   []string{"103.193.149.217"},
		Ports:   []int{9999},
	}})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	if cfg.Route != nil {
		for _, rule := range cfg.Route.Rules {
			if rule.Outbound == SystemDirectOutboundTag {
				t.Fatalf("management rule should not be injected when disabled: %+v", cfg.Route.Rules)
			}
		}
	}
	for _, outbound := range cfg.Outbounds {
		if outbound.Tag == SystemDirectOutboundTag {
			t.Fatalf("system direct outbound should not be injected when no system route uses it: %+v", cfg.Outbounds)
		}
	}
}

func TestBuildConfigWithOutboundsForcesSystemDirectTagToDirect(t *testing.T) {
	cfg, err := BuildConfigWithOutboundsOptions(nil, []db.Outbound{
		{ID: 10, Tag: SystemDirectOutboundTag, Protocol: "blackhole", Enabled: true},
	}, nil, BuildOptions{ManagementDirect: ManagementDirectOptions{
		Enabled: true,
		Hosts:   []string{"103.193.149.217"},
		Ports:   []int{9999},
	}})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	var matches []OutboundConfig
	for _, outbound := range cfg.Outbounds {
		if outbound.Tag == SystemDirectOutboundTag {
			matches = append(matches, outbound)
		}
	}
	if len(matches) != 1 || matches[0].Type != "direct" {
		t.Fatalf("system direct tag must resolve to direct outbound, got %+v", matches)
	}
}

func TestBuildConfigWithOutboundsSkipsLegacyDNSOutboundForSingbox113(t *testing.T) {
	cfg, err := BuildConfigWithOutbounds(nil, []db.Outbound{
		{ID: 3, Tag: "dns", Protocol: "dns", Enabled: true},
		{ID: 10, Tag: "direct", Protocol: "freedom", Enabled: true},
	}, nil)
	if err != nil {
		t.Fatalf("build config with dns outbound: %v", err)
	}
	raw, _ := json.Marshal(cfg)
	text := string(raw)
	if strings.Contains(text, `"type":"dns"`) || strings.Contains(text, `"tag":"singbox-out-3"`) {
		t.Fatalf("sing-box 1.13 config must not contain legacy dns outbound: %s", text)
	}
	if !strings.Contains(text, `"type":"direct"`) {
		t.Fatalf("expected non-dns outbound to remain: %s", text)
	}
}

func TestBuildConfigWithOutboundsSkipsRoutingRuleTargetingLegacyDNSOutbound(t *testing.T) {
	cfg, err := BuildConfigWithOutbounds([]db.Inbound{{
		ID: 2, Remark: "hy2", Protocol: "hysteria2", Core: db.CoreSingbox, Port: 8443, Enabled: true,
	}}, []db.Outbound{
		{ID: 3, Tag: "dns", Protocol: "dns", Enabled: true},
		{ID: 10, Tag: "direct", Protocol: "freedom", Enabled: true},
	}, []db.RoutingRule{
		{ID: 1, InboundTag: "inbound-2-hysteria2", OutboundID: 3, OutboundTag: "dns", Protocol: "dns", Enabled: true},
	})
	if err != nil {
		t.Fatalf("dns routing rule should be skipped for sing-box 1.13: %v", err)
	}
	if cfg.Route != nil && len(cfg.Route.Rules) > 0 {
		t.Fatalf("dns routing rule should not target removed outbound: %+v", cfg.Route.Rules)
	}
}

func TestBuildConfigWithOutboundsCompilesHTTPSOutbound(t *testing.T) {
	cfg, err := BuildConfigWithOutbounds(nil, []db.Outbound{
		{ID: 14, Tag: "proxy-https", Protocol: "https", Address: "127.0.0.1", Port: 8443, Username: "sam", Password: "secret", Enabled: true},
	}, nil)
	if err != nil {
		t.Fatalf("build config with https outbound: %v", err)
	}
	raw, _ := json.Marshal(cfg)
	text := string(raw)
	for _, want := range []string{`"tag":"singbox-out-14"`, `"type":"http"`, `"server":"127.0.0.1"`, `"server_port":8443`} {
		if !strings.Contains(text, want) {
			t.Fatalf("https outbound config missing %q: %s", want, text)
		}
	}
}

func TestBuildConfigWithOutboundsAppliesSubscriptionSettings(t *testing.T) {
	cfg, err := BuildConfigWithOutbounds(nil, []db.Outbound{
		{
			ID: 31, Tag: "sub-vless", Protocol: "vless", Address: "edge.example.com", Port: 443,
			Username: "11111111-1111-4111-8111-111111111111", Enabled: true,
			SettingsJSON: `{"security":"reality","network":"ws","sni":"www.example.com","host":"cdn.example.com","path":"/ws","flow":"xtls-rprx-vision","fp":"chrome","pbk":"PUB","sid":"01","alpn":["h2"]}`,
		},
		{
			ID: 32, Tag: "sub-ss", Protocol: "shadowsocks", Address: "ss.example.com", Port: 8388,
			Username: "aes-128-gcm", Password: "secret", Enabled: true,
			SettingsJSON: `{"method":"aes-128-gcm"}`,
		},
	}, nil)
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	raw, _ := json.Marshal(cfg)
	text := string(raw)
	for _, want := range []string{`"tag":"singbox-out-31"`, `"flow":"xtls-rprx-vision"`, `"tls"`, `"reality"`, `"public_key":"PUB"`, `"short_id":"01"`, `"transport"`, `"type":"ws"`, `"Host":"cdn.example.com"`, `"path":"/ws"`, `"method":"aes-128-gcm"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("subscription outbound config missing %q: %s", want, text)
		}
	}
}

func TestBuildConfigWithOutboundsSkipsXrayRoutingRulesBeforeValidatingOutbound(t *testing.T) {
	cfg, err := BuildConfigWithOutbounds([]db.Inbound{{
		ID: 1, Remark: "edge", Protocol: "vless", Core: db.CoreXray, Port: 443, Enabled: true,
	}}, []db.Outbound{
		{ID: 11, Tag: "shared-socks", Protocol: "socks", Address: "127.0.0.1", Port: 1080, Enabled: true},
	}, []db.RoutingRule{
		{ID: 91, InboundTag: "inbound-1-vless", OutboundID: 11, OutboundTag: "shared-socks", Enabled: true},
	})
	if err != nil {
		t.Fatalf("sing-box should skip xray routing rule before validating outbound: %v", err)
	}
	if cfg.Route != nil && len(cfg.Route.Rules) > 0 {
		t.Fatalf("xray route leaked into sing-box routing: %+v", cfg.Route.Rules)
	}
}

func TestBuildConfigWithOutboundsSkipsStaleInboundTagBeforeValidatingOutbound(t *testing.T) {
	cfg, err := BuildConfigWithOutbounds([]db.Inbound{{
		ID: 2, Remark: "hy2", Protocol: "hysteria2", Core: db.CoreSingbox, Port: 8443, Enabled: true,
	}}, []db.Outbound{
		{ID: 11, Tag: "shared-socks", Protocol: "socks", Address: "127.0.0.1", Port: 1080, Enabled: true},
	}, []db.RoutingRule{
		{ID: 94, InboundTag: "deleted-xray-in", OutboundID: 11, OutboundTag: "shared-socks", Enabled: true},
	})
	if err != nil {
		t.Fatalf("sing-box should skip stale inbound_tag before validating outbound: %v", err)
	}
	if cfg.Route != nil && len(cfg.Route.Rules) > 0 {
		t.Fatalf("stale route leaked into sing-box routing: %+v", cfg.Route.Rules)
	}
}

func TestBuildConfigWithOutboundsTrimsInboundTagBeforeAliasLookup(t *testing.T) {
	cfg, err := BuildConfigWithOutbounds([]db.Inbound{{
		ID: 2, Remark: "hy2", Protocol: "hysteria2", Core: db.CoreSingbox, Port: 8443, Enabled: true,
	}}, []db.Outbound{{ID: 1, Tag: "direct", Protocol: "freedom", Enabled: true}}, []db.RoutingRule{
		{ID: 98, InboundTag: " inbound-2-hysteria2 ", OutboundID: 1, OutboundTag: "direct", Domain: "example.com", Enabled: true},
		{ID: 99, InboundTag: " missing-inbound ", OutboundID: 1, OutboundTag: "direct", Domain: "missing.example", Enabled: true},
	})
	if err != nil {
		t.Fatalf("build config with padded inbound_tag: %v", err)
	}
	if cfg.Route == nil || len(cfg.Route.Rules) != 1 {
		t.Fatalf("expected only padded known inbound_tag route, got %+v", cfg.Route)
	}
	if got := cfg.Route.Rules[0].Inbound; len(got) != 1 || got[0] != "hy2-inbound-2" {
		t.Fatalf("expected trimmed inbound tag restriction, got %+v", got)
	}
}

func TestBuildConfigWithOutboundsReportsMissingOutboundProfileForApplicableRule(t *testing.T) {
	_, err := BuildConfigWithOutbounds([]db.Inbound{{
		ID: 2, Remark: "hy2", Protocol: "hysteria2", Core: db.CoreSingbox, Port: 8443, Enabled: true,
	}}, []db.Outbound{{ID: 1, Tag: "direct", Protocol: "freedom", Enabled: true}}, []db.RoutingRule{
		{ID: 92, InboundTag: "inbound-2-hysteria2", OutboundID: 99, OutboundTag: "missing", Enabled: true},
	})
	if err == nil || !strings.Contains(err.Error(), "missing outbound profile") {
		t.Fatalf("expected clear missing outbound error, got %v", err)
	}
}

func TestBuildConfigWithOutboundsUsesInboundIDBeforeTagSnapshot(t *testing.T) {
	cfg, err := BuildConfigWithOutbounds([]db.Inbound{
		{ID: 2, Remark: "hy2-a", Protocol: "hysteria2", Core: db.CoreSingbox, Port: 8443, Enabled: true},
		{ID: 3, Remark: "hy2-b", Protocol: "hysteria2", Core: db.CoreSingbox, Port: 9443, Enabled: true},
		{ID: 4, Remark: "hy2-disabled", Protocol: "hysteria2", Core: db.CoreSingbox, Port: 10443, Enabled: false},
	}, []db.Outbound{{ID: 1, Tag: "direct", Protocol: "freedom", Enabled: true}}, []db.RoutingRule{
		{ID: 95, InboundID: 3, InboundTag: "hy2-a", OutboundID: 1, OutboundTag: "direct", Domain: "example.com", Enabled: true},
		{ID: 96, InboundID: 2, InboundTag: "", OutboundID: 1, OutboundTag: "direct", Domain: "example.org", Enabled: true},
		{ID: 97, InboundID: 4, OutboundID: 1, OutboundTag: "direct", Domain: "disabled.example", Enabled: true},
	})
	if err != nil {
		t.Fatalf("build config with inbound_id routing rules: %v", err)
	}
	if cfg.Route == nil || len(cfg.Route.Rules) != 2 {
		t.Fatalf("expected two route rules, got %+v", cfg.Route)
	}
	if got := cfg.Route.Rules[0].Inbound; len(got) != 1 || got[0] != "hy2-inbound-3" {
		t.Fatalf("expected inbound_id to override stale inbound_tag, got %+v", got)
	}
	if got := cfg.Route.Rules[1].Inbound; len(got) != 1 || got[0] != "hy2-inbound-2" {
		t.Fatalf("expected inbound_id to work without inbound_tag snapshot, got %+v", got)
	}
}

func TestBuildConfigWithOutboundsValidatesBasicOutboundCredentials(t *testing.T) {
	cases := []db.Outbound{
		{ID: 21, Tag: "missing-vless-uuid", Protocol: "vless", Address: "127.0.0.1", Port: 443, Enabled: true},
		{ID: 26, Tag: "invalid-vless-uuid", Protocol: "vless", Address: "127.0.0.1", Port: 443, Username: "not-a-uuid", Enabled: true},
		{ID: 22, Tag: "missing-trojan-password", Protocol: "trojan", Address: "127.0.0.1", Port: 443, Enabled: true},
		{ID: 23, Tag: "missing-ss-method", Protocol: "shadowsocks", Address: "127.0.0.1", Port: 8388, Password: "secret", Enabled: true},
		{ID: 24, Tag: "missing-tuic-uuid", Protocol: "tuic", Address: "127.0.0.1", Port: 443, Password: "secret", Enabled: true},
		{ID: 25, Tag: "missing-shadowtls-password", Protocol: "shadowtls", Address: "127.0.0.1", Port: 443, Enabled: true},
	}
	for _, outbound := range cases {
		t.Run(outbound.Protocol, func(t *testing.T) {
			_, err := BuildConfigWithOutbounds(nil, []db.Outbound{outbound}, nil)
			if err == nil {
				t.Fatalf("expected %s outbound validation error", outbound.Protocol)
			}
		})
	}
}

func TestBuildConfig_PortAllocation(t *testing.T) {
	inbounds := []db.Inbound{}
	for i := 0; i < 3; i++ {
		inbounds = append(inbounds, db.Inbound{
			ID: int64(i + 1), Protocol: "hysteria2", Port: 21000 + i, Enabled: true,
			Clients: []db.Client{{ID: 1, UUID: "p", Enabled: true}},
		})
	}

	cfg := BuildConfig(inbounds)
	if len(cfg.Inbounds) != 3 {
		t.Fatalf("expected 3 inbounds, got %d", len(cfg.Inbounds))
	}
	for i, ib := range cfg.Inbounds {
		expectedPort := SBBasePort + i
		if ib.ListenPort != expectedPort {
			t.Errorf("inbound %d: expected port %d, got %d", i, expectedPort, ib.ListenPort)
		}
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	// Use temp dir
	origCert := CertFile
	origKey := KeyFile
	origDir := DefaultConfigDir
	defer func() {
		CertFile = origCert
		KeyFile = origKey
		DefaultConfigDir = origDir
	}()

	certFile := t.TempDir() + "/server.crt"
	keyFile := t.TempDir() + "/server.key"
	DefaultConfigDir = t.TempDir()
	CertFile = certFile
	KeyFile = keyFile

	if err := GenerateSelfSignedCert(); err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}

	if _, err := os.Stat(certFile); err != nil {
		t.Errorf("cert file not created: %v", err)
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Errorf("key file not created: %v", err)
	}
}

func TestNextPort(t *testing.T) {
	if p := NextPort(0); p != SBBasePort {
		t.Errorf("expected %d, got %d", SBBasePort, p)
	}
	if p := NextPort(1); p != SBBasePort+1 {
		t.Errorf("expected %d, got %d", SBBasePort+1, p)
	}
}

func TestBuildConfig_TUICInbound(t *testing.T) {
	inbounds := []db.Inbound{
		{
			ID: 1, Protocol: "tuic", Port: 21010, Enabled: true,
			TuicCongestionControl: "cubic",
			TuicZeroRTT:           true,
			Clients: []db.Client{
				{ID: 1, UUID: "tuic-pass-1", Email: "user1@test", Enabled: true},
			},
		},
	}

	cfg := BuildConfig(inbounds)

	if len(cfg.Inbounds) != 1 {
		t.Fatalf("expected 1 inbound, got %d", len(cfg.Inbounds))
	}
	ib := cfg.Inbounds[0]
	if ib.Type != "tuic" {
		t.Errorf("expected type tuic, got %s", ib.Type)
	}
	if ib.ListenPort != 21010 {
		t.Errorf("expected user-facing inbound port 21010, got %d", ib.ListenPort)
	}
	if ib.TLS == nil || !ib.TLS.Enabled {
		t.Error("expected TLS enabled for TUIC")
	}
	if ib.CongestionControl != "cubic" {
		t.Errorf("expected congestion_control cubic, got %s", ib.CongestionControl)
	}
	if !ib.ZeroRTTHandshake {
		t.Error("expected zero_rtt_handshake true")
	}
	if len(ib.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(ib.Users))
	}
	if ib.Users[0].UUID == "" {
		t.Errorf("expected non-empty uuid, got empty")
	}
	if ib.Users[0].Password != "tuic-pass-1" {
		t.Errorf("expected password tuic-pass-1, got %s", ib.Users[0].Password)
	}
	// UUID should be a valid UUID format
	if len(ib.Users[0].UUID) != 36 {
		t.Errorf("expected uuid length 36, got %d: %s", len(ib.Users[0].UUID), ib.Users[0].UUID)
	}
}

func TestBuildConfig_TUICUserCredentialsAreStable(t *testing.T) {
	inbounds := []db.Inbound{
		{
			ID: 1, Protocol: "tuic", Port: 21010, Enabled: true,
			Clients: []db.Client{{ID: 1, UUID: "123e4567-e89b-12d3-a456-426614174000", Email: "user1@test", Enabled: true}},
		},
	}

	first := BuildConfig(inbounds)
	second := BuildConfig(inbounds)

	if first.Inbounds[0].Users[0].UUID != second.Inbounds[0].Users[0].UUID {
		t.Fatalf("TUIC user UUID must be stable across config builds, got %q then %q", first.Inbounds[0].Users[0].UUID, second.Inbounds[0].Users[0].UUID)
	}
	if first.Inbounds[0].Users[0].Password != second.Inbounds[0].Users[0].Password {
		t.Fatalf("TUIC user password must be stable across config builds")
	}
}

func TestBuildConfig_WireGuardInbound(t *testing.T) {
	// WireGuard inbound requires sing-box >= 1.14
	// Currently skipped — test verifies it's NOT added to the config
	inbounds := []db.Inbound{
		{
			ID: 1, Protocol: "wireguard", Port: 21020, Enabled: true,
			WgPrivateKey:    "server-private-key-abc",
			WgAddress:       "10.0.0.1/24",
			WgPeerPublicKey: "peer-public-key-xyz",
			WgAllowedIPs:    "0.0.0.0/0, ::/0",
			WgEndpoint:      "peer.example.com:51820",
			WgPresharedKey:  "preshared-key-123",
			WgMTU:           1420,
			Clients:         []db.Client{{ID: 1, UUID: "ignored", Enabled: true}},
		},
	}

	cfg := BuildConfig(inbounds)

	// WireGuard skipped — expect 0 inbounds
	if len(cfg.Inbounds) != 0 {
		t.Fatalf("expected 0 inbounds (wireguard skipped), got %d", len(cfg.Inbounds))
	}
}

func TestBuildConfig_ShadowTLSInbound(t *testing.T) {
	inbounds := []db.Inbound{
		{
			ID: 1, Protocol: "shadowtls", Port: 21030, Enabled: true,
			ShadowTLSPassword: "shadow-pass-1",
			ShadowTLSVersion:  2,
			TLSSNI:            "cloudflare.com",
			Clients: []db.Client{
				{ID: 1, UUID: "user-pass-1", Email: "user1@test", Enabled: true},
			},
		},
	}

	cfg := BuildConfig(inbounds)

	if len(cfg.Inbounds) != 1 {
		t.Fatalf("expected 1 inbound, got %d", len(cfg.Inbounds))
	}
	ib := cfg.Inbounds[0]
	if ib.Type != "shadowtls" {
		t.Errorf("expected type shadowtls, got %s", ib.Type)
	}
	if ib.Password != "" {
		t.Errorf("expected no inbound password (v1.13 compat), got %s", ib.Password)
	}
	if ib.Version != 2 {
		t.Errorf("expected version 2, got %d", ib.Version)
	}
	if ib.Handshake == nil || ib.Handshake.Server != "cloudflare.com" || ib.Handshake.ServerPort != 443 {
		t.Errorf("expected handshake server cloudflare.com:443, got %+v", ib.Handshake)
	}
	if ib.TLS != nil {
		t.Error("expected nil TLS for shadowtls (inbound has no TLS config)")
	}
	if len(ib.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(ib.Users))
	}
	if ib.Users[0].Password != "user-pass-1" {
		t.Errorf("expected user password, got %s", ib.Users[0].Password)
	}
}

func TestBuildConfig_MixedSingBoxProtocols(t *testing.T) {
	inbounds := []db.Inbound{
		{ID: 1, Protocol: "vless", Port: 10001, Enabled: true,
			Clients: []db.Client{{ID: 1, UUID: "u1", Enabled: true}}},
		{ID: 2, Protocol: "hysteria2", Port: 21001, Enabled: true,
			Clients: []db.Client{{ID: 2, UUID: "p2", Enabled: true}}},
		{ID: 3, Protocol: "tuic", Port: 21002, Enabled: true,
			Clients: []db.Client{{ID: 3, UUID: "tp3", Enabled: true}}},
		{ID: 4, Protocol: "wireguard", Port: 21003, Enabled: true,
			WgPrivateKey: "wg-key", WgAddress: "10.0.0.1/24", WgPeerPublicKey: "peer-key"},
		{ID: 5, Protocol: "shadowtls", Port: 21004, Enabled: true,
			ShadowTLSPassword: "st-pass",
			Clients:           []db.Client{{ID: 5, UUID: "st-user", Enabled: true}}},
		{ID: 6, Protocol: "shadowsocks", Port: 30001, Enabled: true,
			Clients: []db.Client{{ID: 6, UUID: "ss-u", Enabled: true}}},
	}

	cfg := BuildConfig(inbounds)

	// Expect 3 sing-box inbounds (hysteria2, tuic, shadowtls; wireguard skipped)
	if len(cfg.Inbounds) != 3 {
		t.Fatalf("expected 3 sing-box inbounds (wireguard skipped), got %d", len(cfg.Inbounds))
	}
	types := make(map[string]bool)
	for _, ib := range cfg.Inbounds {
		types[ib.Type] = true
	}
	for _, proto := range []string{"hysteria2", "tuic", "shadowtls"} {
		if !types[proto] {
			t.Errorf("missing sing-box protocol: %s", proto)
		}
	}
	if types["vless"] || types["shadowsocks"] {
		t.Error("non-sing-box protocols should be skipped")
	}
}

func assertJSONStrings(t *testing.T, raw interface{}, want []string) {
	t.Helper()
	values, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("expected JSON string array, got %#v", raw)
	}
	if len(values) != len(want) {
		t.Fatalf("unexpected array length: got %#v want %#v", values, want)
	}
	for i := range want {
		if values[i] != want[i] {
			t.Fatalf("unexpected array value at %d: got %#v want %#v", i, values[i], want[i])
		}
	}
}
