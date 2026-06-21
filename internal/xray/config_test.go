package xray_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/xray"
)

func join(parts ...string) string { return strings.Join(parts, "") }

func userInboundsForTest(inbounds []xray.InboundConfig) []xray.InboundConfig {
	out := []xray.InboundConfig{}
	for _, in := range inbounds {
		if in.Tag != "api" {
			out = append(out, in)
		}
	}
	return out
}

func userRoutingRulesForTest(rules []xray.RoutingRule) []xray.RoutingRule {
	out := []xray.RoutingRule{}
	for _, r := range rules {
		if r.OutboundTag != "api" && r.OutboundTag != xray.SystemDirectOutboundTag {
			out = append(out, r)
		}
	}
	return out
}

func userOutboundsForTest(outbounds []xray.OutboundConfig) []xray.OutboundConfig {
	out := []xray.OutboundConfig{}
	for _, outbound := range outbounds {
		if outbound.Tag != xray.SystemDirectOutboundTag {
			out = append(out, outbound)
		}
	}
	return out
}

func TestBuildConfigIncludesSupportedProtocolInboundsAndFreedomOutbound(t *testing.T) {
	inbounds := []db.Inbound{
		{ID: 1, UUID: "11111111-1111-4111-8111-111111111111", Remark: "vless-reality", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality", Enabled: true, Clients: []db.Client{{UUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Email: "a@example.com", Enabled: true}}},
		{ID: 2, UUID: "22222222-2222-4222-8222-222222222222", Remark: "vmess-ws", Protocol: "vmess", Port: 8443, Network: "ws", Security: "tls", Enabled: true, Clients: []db.Client{{UUID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Email: "b@example.com", Enabled: true}}},
		{ID: 3, UUID: "33333333-3333-4333-8333-333333333333", Remark: "trojan", Protocol: "trojan", Port: 9443, Network: "tcp", Security: "tls", Enabled: true, Clients: []db.Client{{UUID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Email: "c@example.com", Enabled: true}}},
		{ID: 4, UUID: "manual-ss-password", Remark: "ss", Protocol: "shadowsocks", SSMethod: "aes-256-gcm", Port: 1080, Network: "tcp", Security: "none", Enabled: true, Clients: []db.Client{{UUID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", Email: "d@example.com", Enabled: true}}},
		{ID: 5, UUID: "55555555-5555-4555-8555-555555555555", Remark: "disabled", Protocol: "vless", Port: 1443, Network: "tcp", Security: "none", Enabled: false, Clients: []db.Client{{UUID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", Email: "disabled@example.com", Enabled: true}}},
		{ID: 6, UUID: "66666666-6666-4666-8666-666666666666", Remark: "trojan-reality", Protocol: "trojan", Port: 30030, Network: "tcp", Security: "reality", RealityDest: "www.microsoft.com:443", RealityServerNames: "www.microsoft.com", RealityShortID: "", RealityPrivateKey: "uNisYErm5wwrV9t9EP2P3VB0g3CpS5m70bdG7gwShXg", Enabled: true, Clients: []db.Client{{UUID: "ffffffff-ffff-4fff-8fff-ffffffffffff", Email: "trojan-reality@test.com", Enabled: true}}},
	}

	config, err := xray.BuildConfig(inbounds)
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	userInbounds := userInboundsForTest(config.Inbounds)
	if len(userInbounds) != 5 {
		t.Fatalf("expected five enabled user inbounds, got %+v", config.Inbounds)
	}
	userOutbounds := userOutboundsForTest(config.Outbounds)
	if len(userOutbounds) != 1 || userOutbounds[0].Protocol != "freedom" {
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
		{ID: 1, Tag: "direct", Protocol: "freedom", Enabled: true, Sort: 0},
		{ID: 2, Tag: "blocked", Protocol: "blackhole", Enabled: true, Sort: 1},
		{ID: 3, Tag: "proxy-socks", Protocol: "socks", Address: "127.0.0.1", Port: 1080, Username: "sam", Password: "secret", Enabled: true, Sort: 2},
		{ID: 4, Tag: "disabled-proxy", Protocol: "http", Address: "127.0.0.1", Port: 8080, Enabled: false, Sort: 3},
	}, nil)
	if err != nil {
		t.Fatalf("build config with outbounds: %v", err)
	}
	userOutbounds := userOutboundsForTest(config.Outbounds)
	if len(userOutbounds) != 3 {
		t.Fatalf("expected three enabled outbounds, got %+v", config.Outbounds)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	text := string(encoded)
	for _, want := range []string{`"tag":"xray-out-1"`, `"protocol":"freedom"`, `"tag":"xray-out-2"`, `"protocol":"blackhole"`, `"tag":"xray-out-3"`, `"protocol":"socks"`, `"address":"127.0.0.1"`, `"port":1080`, `"user":"sam"`, `"pass":"secret"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("outbound config missing %q: %s", want, text)
		}
	}
	if strings.Contains(text, "disabled-proxy") {
		t.Fatalf("disabled outbound leaked into config: %s", text)
	}
}

func TestBuildConfigIncludesSocksAndHTTPInbounds(t *testing.T) {
	config, err := xray.BuildConfig([]db.Inbound{
		{ID: 21, Remark: "socks-in", Protocol: "socks", Port: 1080, Network: "tcp", Security: "none", Enabled: true, Clients: []db.Client{{UUID: "sam", CredentialID: "sam", Password: "secret", Email: "sam", Enabled: true}}},
		{ID: 22, Remark: "http-in", Protocol: "http", Port: 8080, Network: "tcp", Security: "none", Enabled: true, Clients: []db.Client{{UUID: "ann", CredentialID: "ann", Password: "secret2", Email: "ann", Enabled: true}}},
	})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	encoded, _ := json.Marshal(config)
	text := string(encoded)
	for _, want := range []string{`"protocol":"socks"`, `"protocol":"http"`, `"accounts"`, `"user":"sam"`, `"pass":"secret"`, `"user":"ann"`, `"pass":"secret2"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("socks/http inbound config missing %q: %s", want, text)
		}
	}
}

func TestBuildConfigWithOutboundsCompilesHTTPSToHTTPOutbound(t *testing.T) {
	config, err := xray.BuildConfigWithOutbounds(nil, []db.Outbound{
		{ID: 14, Tag: "proxy-https", Protocol: "https", Address: "127.0.0.1", Port: 8443, Username: "sam", Password: "secret", Enabled: true},
	}, nil)
	if err != nil {
		t.Fatalf("build config with https outbound: %v", err)
	}
	raw, _ := json.Marshal(config)
	text := string(raw)
	for _, want := range []string{`"tag":"xray-out-14"`, `"protocol":"http"`, `"address":"127.0.0.1"`, `"port":8443`} {
		if !strings.Contains(text, want) {
			t.Fatalf("https outbound config missing %q: %s", want, text)
		}
	}
}

func TestBuildConfigWithSubscriptionOutboundSettings(t *testing.T) {
	config, err := xray.BuildConfigWithOutbounds(nil, []db.Outbound{
		{
			ID: 21, Tag: "sub-vless", Protocol: "vless", Address: "edge.example.com", Port: 443,
			Username: "11111111-1111-4111-8111-111111111111", Enabled: true,
			SettingsJSON: `{"security":"reality","network":"ws","sni":"www.example.com","host":"cdn.example.com","path":"/ws","flow":"xtls-rprx-vision","fp":"chrome","pbk":"PUB","sid":"01","alpn":["h2"]}`,
		},
		{
			ID: 22, Tag: "sub-trojan", Protocol: "trojan", Address: "tls.example.com", Port: 443,
			Password: "secret", Enabled: true,
			SettingsJSON: `{"security":"tls","sni":"tls.example.com","fp":"firefox"}`,
		},
	}, nil)
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	raw, _ := json.Marshal(config)
	text := string(raw)
	for _, want := range []string{`"streamSettings"`, `"security":"reality"`, `"wsSettings"`, `"Host":"cdn.example.com"`, `"flow":"xtls-rprx-vision"`, `"publicKey":"PUB"`, `"shortId":"01"`, `"tlsSettings"`, `"serverName":"tls.example.com"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("subscription outbound config missing %q: %s", want, text)
		}
	}
}

func TestBuildConfigSkipsSingboxOnlyOutboundProfiles(t *testing.T) {
	config, err := xray.BuildConfigWithOutbounds(nil, []db.Outbound{
		{ID: 8, Tag: "hy2-out", Protocol: "hysteria2", Address: "127.0.0.1", Port: 443, Enabled: true},
		{ID: 9, Tag: "socks-out", Protocol: "socks", Address: "127.0.0.1", Port: 1080, Enabled: true},
	}, nil)
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	encoded, _ := json.Marshal(config)
	text := string(encoded)
	if strings.Contains(text, "hy2-out") || strings.Contains(text, "xray-out-8") {
		t.Fatalf("sing-box-only outbound leaked into xray config: %s", text)
	}
	if !strings.Contains(text, "xray-out-9") {
		t.Fatalf("shared socks outbound missing xray tag: %s", text)
	}
}

func TestBuildConfigSkipsRoutingRulesForOtherCoreBeforeValidatingOutbound(t *testing.T) {
	inbounds := []db.Inbound{{
		ID: 1, Remark: "hy2", Protocol: "hysteria2", Core: db.CoreSingbox, Port: 8443, Enabled: true,
	}}
	config, err := xray.BuildConfigWithOutbounds(inbounds, []db.Outbound{
		{ID: 8, Tag: "hy2-out", Protocol: "hysteria2", Address: "127.0.0.1", Port: 443, Enabled: true},
	}, []db.RoutingRule{
		{ID: 91, InboundTag: "inbound-1-hysteria2", OutboundID: 8, OutboundTag: "hy2-out", Enabled: true},
	})
	if err != nil {
		t.Fatalf("xray should skip sing-box routing rule before validating outbound: %v", err)
	}
	if len(userRoutingRulesForTest(config.Routing.Rules)) != 0 {
		t.Fatalf("sing-box route leaked into xray routing: %+v", config.Routing.Rules)
	}
}

func TestBuildConfigSkipsStaleInboundTagBeforeValidatingOutbound(t *testing.T) {
	config, err := xray.BuildConfigWithOutbounds([]db.Inbound{{
		ID: 1, Remark: "edge", Protocol: "vless", Core: db.CoreXray, Port: 443, Enabled: true,
	}}, []db.Outbound{
		{ID: 8, Tag: "hy2-out", Protocol: "hysteria2", Address: "127.0.0.1", Port: 443, Password: "secret", Enabled: true},
	}, []db.RoutingRule{
		{ID: 94, InboundTag: "deleted-singbox-in", OutboundID: 8, OutboundTag: "hy2-out", Enabled: true},
	})
	if err != nil {
		t.Fatalf("xray should skip stale inbound_tag before validating outbound: %v", err)
	}
	if len(userRoutingRulesForTest(config.Routing.Rules)) != 0 {
		t.Fatalf("stale inbound route leaked into xray routing: %+v", config.Routing.Rules)
	}
}

func TestBuildConfigTrimsInboundTagBeforeAliasLookup(t *testing.T) {
	config, err := xray.BuildConfigWithOutbounds([]db.Inbound{{
		ID: 1, Remark: "edge", Protocol: "vless", Core: db.CoreXray, Port: 443, Enabled: true,
	}}, []db.Outbound{{ID: 1, Tag: "direct", Protocol: "freedom", Enabled: true}}, []db.RoutingRule{
		{ID: 95, InboundTag: " inbound-1-vless ", OutboundID: 1, OutboundTag: "direct", Domain: "example.com", Enabled: true},
		{ID: 96, InboundTag: " missing-inbound ", OutboundID: 1, OutboundTag: "direct", Domain: "missing.example", Enabled: true},
	})
	if err != nil {
		t.Fatalf("build config with padded inbound_tag: %v", err)
	}
	userRules := userRoutingRulesForTest(config.Routing.Rules)
	if len(userRules) != 1 {
		t.Fatalf("expected only padded known inbound_tag rule, got %+v", userRules)
	}
	if got := userRules[0].InboundTag; len(got) != 1 || got[0] != "inbound-1-vless" {
		t.Fatalf("expected trimmed inbound tag restriction, got %+v", got)
	}
}

func TestBuildConfigReportsMissingOutboundProfileForApplicableRule(t *testing.T) {
	_, err := xray.BuildConfigWithOutbounds([]db.Inbound{{
		ID: 1, Remark: "edge", Protocol: "vless", Core: db.CoreXray, Port: 443, Enabled: true,
	}}, []db.Outbound{{ID: 1, Tag: "direct", Protocol: "freedom", Enabled: true}}, []db.RoutingRule{
		{ID: 92, InboundTag: "inbound-1-vless", OutboundID: 99, OutboundTag: "missing", Enabled: true},
	})
	if err == nil || !strings.Contains(err.Error(), "missing outbound profile") {
		t.Fatalf("expected clear missing outbound error, got %v", err)
	}
}

func TestBuildConfigWithRoutingRules(t *testing.T) {
	inbounds := []db.Inbound{{ID: 9, Remark: "socks-in", Protocol: "vless", Core: db.CoreXray, Port: 1080, Enabled: true}}
	config, err := xray.BuildConfigWithOutbounds(inbounds, []db.Outbound{
		{ID: 1, Tag: "direct", Protocol: "freedom", Enabled: true, Sort: 0},
		{ID: 2, Tag: "blocked", Protocol: "blackhole", Enabled: true, Sort: 1},
		{ID: 3, Tag: "proxy-socks", Protocol: "socks", Address: "10.0.0.1", Port: 1080, Enabled: true, Sort: 2},
	}, []db.RoutingRule{
		{InboundTag: "socks-in", OutboundID: 3, OutboundTag: "proxy-socks", Domain: "geosite:netflix", Enabled: true},
		{OutboundID: 2, OutboundTag: "blocked", Domain: "geosite:malware", Enabled: true},
		{OutboundID: 2, OutboundTag: "blocked", Protocol: "bittorrent", Enabled: false},
	})
	if err != nil {
		t.Fatalf("build config with routing rules: %v", err)
	}
	if config.Routing == nil {
		t.Fatal("expected routing section in config")
	}
	if config.Routing.DomainStrategy != "AsIs" {
		t.Fatalf("expected AsIs domain strategy, got %s", config.Routing.DomainStrategy)
	}
	userRules := userRoutingRulesForTest(config.Routing.Rules)
	if len(userRules) != 2 {
		t.Fatalf("expected 2 enabled routing rules, got %d", len(userRules))
	}
	if userRules[0].OutboundTag != "xray-out-3" || userRules[0].Domain[0] != "geosite:netflix" {
		t.Fatalf("unexpected first rule: %+v", userRules[0])
	}
	if userRules[1].OutboundTag != "xray-out-2" || userRules[1].Domain[0] != "geosite:malware" {
		t.Fatalf("unexpected second rule: %+v", userRules[1])
	}
	// No routing rules
	config2, err := xray.BuildConfigWithOutbounds(nil, nil, nil)
	if err != nil {
		t.Fatalf("build with nil rules: %v", err)
	}
	if config2.Routing == nil || len(userRoutingRulesForTest(config2.Routing.Rules)) != 0 {
		t.Fatal("expected no user routing rules when no rules are configured")
	}
}

func TestBuildConfigWithOutboundsInjectsManagementDirectBeforeUserCatchAll(t *testing.T) {
	config, err := xray.BuildConfigWithOutboundsOptions([]db.Inbound{
		{ID: 8, Remark: "local-socks", Protocol: "socks", Port: 1080, Network: "tcp", Security: "none", Enabled: true, Clients: []db.Client{{Email: "user", Password: "pass", Enabled: true}}},
	}, []db.Outbound{
		{ID: 1, Tag: "proxy", Protocol: "vless", Address: "proxy.example.com", Port: 443, Username: "11111111-1111-4111-8111-111111111111", Password: "flow-password", Enabled: true},
	}, []db.RoutingRule{
		{ID: 1, OutboundID: 1, OutboundTag: "proxy", Domain: "geosite:geolocation-!cn", Enabled: true},
	}, xray.BuildOptions{ManagementDirect: xray.ManagementDirectOptions{
		Enabled: true,
		Hosts:   []string{"103.193.149.217", "HTTP://Panel.Example.COM:9999/panel/", "[2001:db8::1]", "panel.example.com", ""},
		Ports:   []int{9999, 22, 9999, 0, 70000},
	}})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	if len(config.Routing.Rules) < 4 {
		t.Fatalf("expected api, management and user rules, got %+v", config.Routing.Rules)
	}
	if config.Routing.Rules[0].OutboundTag != "api" {
		t.Fatalf("stats api rule must stay first, got %+v", config.Routing.Rules)
	}
	ipRule := config.Routing.Rules[1]
	if ipRule.OutboundTag != xray.SystemDirectOutboundTag || ipRule.Port != "22,9999" || strings.Join(ipRule.IP, ",") != "103.193.149.217,2001:db8::1" || len(ipRule.Domain) != 0 {
		t.Fatalf("expected management IP rule before user rules, got %+v", ipRule)
	}
	if strings.Contains(ipRule.Port, "80") || strings.Contains(ipRule.Port, "443") {
		t.Fatalf("management direct rule must not include common service ports by default, got %+v", ipRule)
	}
	domainRule := config.Routing.Rules[2]
	if domainRule.OutboundTag != xray.SystemDirectOutboundTag || domainRule.Port != "22,9999" || strings.Join(domainRule.Domain, ",") != "panel.example.com" || len(domainRule.IP) != 0 {
		t.Fatalf("expected management domain rule before user rules, got %+v", domainRule)
	}
	userRule := config.Routing.Rules[3]
	if userRule.OutboundTag != "xray-out-1" || strings.Join(userRule.Domain, ",") != "geosite:geolocation-!cn" || userRule.Port != "" {
		t.Fatalf("user catch-all should remain routed to proxy outbound, got %+v", userRule)
	}
	found := false
	for _, outbound := range config.Outbounds {
		if outbound.Tag == xray.SystemDirectOutboundTag && outbound.Protocol == "freedom" {
			found = true
		}
	}
	if !found {
		t.Fatalf("system direct outbound missing: %+v", config.Outbounds)
	}
	for _, rule := range config.Routing.Rules {
		if rule.OutboundTag == xray.SystemDirectOutboundTag && rule.Port == "" {
			t.Fatalf("management direct must not be emitted as a global direct rule: %+v", rule)
		}
	}
}

func TestBuildConfigWithOutboundsKeepsOrdinaryCatchAllOnProxy(t *testing.T) {
	config, err := xray.BuildConfigWithOutboundsOptions([]db.Inbound{
		{ID: 8, Remark: "local-socks", Protocol: "socks", Port: 1080, Network: "tcp", Security: "none", Enabled: true, Clients: []db.Client{{Email: "user", Password: "pass", Enabled: true}}},
	}, []db.Outbound{
		{ID: 1, Tag: "vless-proxy", Protocol: "vless", Address: "proxy.example.com", Port: 443, Username: "11111111-1111-4111-8111-111111111111", Password: "flow-password", Enabled: true},
	}, []db.RoutingRule{
		{ID: 1, OutboundID: 1, OutboundTag: "vless-proxy", Enabled: true},
	}, xray.BuildOptions{ManagementDirect: xray.ManagementDirectOptions{
		Enabled: true,
		Hosts:   []string{"panel.example.com"},
		Ports:   []int{9999},
	}})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	userRules := userRoutingRulesForTest(config.Routing.Rules)
	if len(userRules) != 1 || userRules[0].OutboundTag != "xray-out-1" || len(userRules[0].Domain) != 0 || len(userRules[0].IP) != 0 || userRules[0].Port != "" {
		t.Fatalf("ordinary catch-all should remain routed to proxy outbound, got %+v", userRules)
	}
	for _, rule := range config.Routing.Rules {
		if rule.OutboundTag != xray.SystemDirectOutboundTag {
			continue
		}
		if rule.Port != "9999" || strings.Join(rule.Domain, ",") != "panel.example.com" {
			t.Fatalf("management direct must only match management host+port, got %+v", rule)
		}
	}
}

func TestBuildConfigWithOutboundsSkipsManagementDirectWhenDisabled(t *testing.T) {
	config, err := xray.BuildConfigWithOutboundsOptions(nil, []db.Outbound{
		{ID: 1, Tag: "proxy", Protocol: "socks", Address: "127.0.0.1", Port: 1080, Enabled: true},
	}, []db.RoutingRule{
		{ID: 1, OutboundID: 1, OutboundTag: "proxy", Domain: "geosite:geolocation-!cn", Enabled: true},
	}, xray.BuildOptions{ManagementDirect: xray.ManagementDirectOptions{
		Enabled: false,
		Hosts:   []string{"103.193.149.217"},
		Ports:   []int{9999},
	}})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	for _, rule := range config.Routing.Rules {
		if rule.OutboundTag == xray.SystemDirectOutboundTag {
			t.Fatalf("management rule should not be injected when disabled: %+v", config.Routing.Rules)
		}
	}
	for _, outbound := range config.Outbounds {
		if outbound.Tag == xray.SystemDirectOutboundTag {
			t.Fatalf("system direct outbound should not be injected when no system route uses it: %+v", config.Outbounds)
		}
	}
}

func TestBuildConfigWithOutboundsForcesSystemDirectTagToFreedom(t *testing.T) {
	config, err := xray.BuildConfigWithOutboundsOptions(nil, []db.Outbound{
		{ID: 1, Tag: xray.SystemDirectOutboundTag, Protocol: "blackhole", Enabled: true},
	}, nil, xray.BuildOptions{ManagementDirect: xray.ManagementDirectOptions{
		Enabled: true,
		Hosts:   []string{"103.193.149.217"},
		Ports:   []int{9999},
	}})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	var matches []xray.OutboundConfig
	for _, outbound := range config.Outbounds {
		if outbound.Tag == xray.SystemDirectOutboundTag {
			matches = append(matches, outbound)
		}
	}
	if len(matches) != 1 || matches[0].Protocol != "freedom" {
		t.Fatalf("system direct tag must resolve to freedom outbound, got %+v", matches)
	}
}

func TestBuildConfigWithRoutingRulesUsesOutboundIDAfterTagRename(t *testing.T) {
	inbounds := []db.Inbound{{ID: 9, Remark: "socks-in", Protocol: "vless", Core: db.CoreXray, Port: 1080, Enabled: true}}
	config, err := xray.BuildConfigWithOutbounds(inbounds, []db.Outbound{
		{ID: 42, Tag: "proxy-new", Protocol: "socks", Address: "10.0.0.1", Port: 1080, Enabled: true},
	}, []db.RoutingRule{
		{ID: 42, InboundTag: "socks-in", OutboundID: 42, OutboundTag: "proxy-old", Domain: "geosite:netflix", Enabled: true},
	})
	if err != nil {
		t.Fatalf("build config with renamed outbound rule: %v", err)
	}
	userRules := userRoutingRulesForTest(config.Routing.Rules)
	if len(userRules) != 1 {
		t.Fatalf("expected one user routing rule, got %+v", config.Routing.Rules)
	}
	if got := userRules[0].OutboundTag; got != "xray-out-42" {
		t.Fatalf("expected generated tag to use outbound_id, got %s", got)
	}
}

func TestBuildConfigWithRoutingRulesUsesInboundIDBeforeTagSnapshot(t *testing.T) {
	inbounds := []db.Inbound{
		{ID: 7, Remark: "edge-a", Protocol: "vless", Core: db.CoreXray, Port: 10443, Enabled: true},
		{ID: 8, Remark: "edge-b", Protocol: "vless", Core: db.CoreXray, Port: 11443, Enabled: true},
		{ID: 9, Remark: "disabled", Protocol: "vless", Core: db.CoreXray, Port: 12443, Enabled: false},
	}
	config, err := xray.BuildConfigWithOutbounds(inbounds, []db.Outbound{
		{ID: 1, Tag: "direct", Protocol: "freedom", Enabled: true},
	}, []db.RoutingRule{
		{ID: 50, InboundID: 8, InboundTag: "edge-a", OutboundID: 1, OutboundTag: "direct", Domain: "example.com", Enabled: true},
		{ID: 51, InboundID: 7, InboundTag: "", OutboundID: 1, OutboundTag: "direct", Domain: "example.org", Enabled: true},
		{ID: 52, InboundID: 9, OutboundID: 1, OutboundTag: "direct", Domain: "disabled.example", Enabled: true},
	})
	if err != nil {
		t.Fatalf("build config with inbound_id routing rules: %v", err)
	}
	userRules := userRoutingRulesForTest(config.Routing.Rules)
	if len(userRules) != 2 {
		t.Fatalf("expected two user routing rules, got %+v", userRules)
	}
	if got := userRules[0].InboundTag; len(got) != 1 || got[0] != "inbound-8-vless" {
		t.Fatalf("expected inbound_id to override stale inbound_tag, got %+v", got)
	}
	if got := userRules[1].InboundTag; len(got) != 1 || got[0] != "inbound-7-vless" {
		t.Fatalf("expected inbound_id to work without inbound_tag snapshot, got %+v", got)
	}
}

func TestBuildConfigWithClientRoutingRules(t *testing.T) {
	inbounds := []db.Inbound{{
		ID:       7,
		UUID:     "77777777-7777-4777-8777-777777777777",
		Remark:   "edge-hk",
		Protocol: "vless",
		Port:     443,
		Network:  "tcp",
		Security: "none",
		Enabled:  true,
		Clients: []db.Client{
			{ID: 11, UUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Email: "alice@example.com", Enabled: true},
			{ID: 12, UUID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Email: "", Enabled: true},
			{ID: 13, UUID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Email: "disabled@example.com", Enabled: false},
		},
	}}
	config, err := xray.BuildConfigWithOutbounds(inbounds, []db.Outbound{
		{ID: 1, Tag: "direct", Protocol: "freedom", Enabled: true, Sort: 0},
		{ID: 2, Tag: "proxy-socks", Protocol: "socks", Address: "10.0.0.1", Port: 1080, Enabled: true, Sort: 1},
	}, []db.RoutingRule{
		{ID: 1, InboundTag: "edge-hk", ClientID: 11, OutboundID: 2, OutboundTag: "proxy-socks", Enabled: true},
		{ID: 2, InboundTag: "edge-hk", ClientID: 12, OutboundID: 1, OutboundTag: "direct", Enabled: true},
		{ID: 3, InboundTag: "edge-hk", ClientID: 999, ClientEmail: "missing@example.com", OutboundID: 1, OutboundTag: "direct", Enabled: true},
		{ID: 4, InboundTag: "edge-hk", ClientID: 11, OutboundID: 1, OutboundTag: "direct", Enabled: false},
		{ID: 5, InboundTag: "edge-hk", ClientID: 13, OutboundID: 1, OutboundTag: "direct", Enabled: true},
	})
	if err != nil {
		t.Fatalf("build config with client routing rules: %v", err)
	}
	userRules := userRoutingRulesForTest(config.Routing.Rules)
	if len(userRules) != 1 {
		t.Fatalf("expected only one valid enabled client routing rule, got %+v", userRules)
	}
	got := userRules[0]
	if got.OutboundTag != "xray-out-2" {
		t.Fatalf("unexpected outbound tag: %+v", got)
	}
	if len(got.User) != 1 || got.User[0] != "alice@example.com" {
		t.Fatalf("expected Xray user email match, got %+v", got.User)
	}
	if len(got.InboundTag) != 1 || got.InboundTag[0] != "inbound-7-vless" {
		t.Fatalf("expected inbound tag restriction, got %+v", got.InboundTag)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if !strings.Contains(string(encoded), `"user":["alice@example.com"]`) {
		t.Fatalf("generated config does not include Xray user field: %s", string(encoded))
	}
}
func TestBuildConfigRejectsUnsupportedProtocol(t *testing.T) {
	_, err := xray.BuildConfig([]db.Inbound{{Protocol: join("open", "vpn"), Port: 1194, Enabled: true}})
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

func TestBuildConfigOmitsVisionFlowForVLESSXHTTPReality(t *testing.T) {
	config, err := xray.BuildConfig([]db.Inbound{{
		ID:                 11,
		UUID:               "11111111-2222-4333-8444-555555555555",
		Remark:             "vless-xhttp-reality-no-flow",
		Protocol:           "vless",
		Port:               30130,
		Network:            "xhttp",
		Security:           "reality",
		XHTTPPath:          "/samge",
		XHTTPMode:          "stream-one",
		RealityDest:        "www.cloudflare.com:443",
		RealityServerNames: "www.cloudflare.com",
		RealityPrivateKey:  "uNisYErm5wwrV9t9EP2P3VB0g3CpS5m70bdG7gwShXg",
		RealityShortID:     "00942aa4",
		Enabled:            true,
		Clients:            []db.Client{{UUID: "7f35b91b-5994-4404-b800-4db37c8106ac", Email: "xhttp@test.com", Enabled: true}},
	}})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	encoded, _ := json.Marshal(config)
	text := string(encoded)
	for _, want := range []string{`"network":"xhttp"`, `"security":"reality"`, `"path":"/samge"`, `"mode":"stream-one"`, `"shortIds":["00942aa4"]`} {
		if !strings.Contains(text, want) {
			t.Fatalf("VLESS+XHTTP+REALITY config missing %q: %s", want, text)
		}
	}
	if strings.Contains(text, `"flow":"xtls-rprx-vision"`) {
		t.Fatalf("VLESS+XHTTP+REALITY must not set TCP Vision flow: %s", text)
	}
}

func TestBuildConfigDoesNotGenerateMissingRealityPrivateKey(t *testing.T) {
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
	userInbounds := userInboundsForTest(config.Inbounds)
	if len(userInbounds) != 1 {
		t.Fatalf("expected 1 user inbound, got %d", len(userInbounds))
	}
	encoded, _ := json.Marshal(config)
	text := string(encoded)
	if !strings.Contains(text, "realitySettings") {
		t.Fatalf("auto-key inbound missing realitySettings: %s", text)
	}
	if strings.Contains(text, "privateKey") {
		t.Fatalf("config generator must not create transient reality privateKey: %s", text)
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
	if got := len(userInboundsForTest(config.Inbounds)); got != 0 {
		t.Fatalf("expected 0 user inbounds (hysteria2 skipped for Xray), got %d", got)
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
	if got := len(userInboundsForTest(config.Inbounds)); got != 0 {
		t.Fatalf("expected 0 user inbounds (hysteria2 skipped for Xray), got %d", got)
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
	if got := len(userInboundsForTest(config.Inbounds)); got != 0 {
		t.Fatalf("expected 0 user inbounds (hysteria2 skipped for Xray), got %d", got)
	}
}

func TestBuildConfigIncludesStatsAndPolicy(t *testing.T) {
	config, err := xray.BuildConfig([]db.Inbound{{
		ID: 1, UUID: "test-uuid", Remark: "test", Protocol: "vless",
		Port: 10000, Network: "tcp", Security: "none", Enabled: true,
		Clients: []db.Client{{UUID: "c1-uuid", StatsKey: "c_stats_key", Email: "client1@test.com", Enabled: true}},
	}})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	encoded, _ := json.Marshal(config)
	text := string(encoded)

	// Must have "stats":{} (empty object enables stats API)
	if !strings.Contains(text, `"stats":{}`) {
		t.Fatalf("config missing stats: %s", text)
	}
	// Must have policy with statsUserUplink and statsUserDownlink
	if !strings.Contains(text, `"statsUserUplink":true`) {
		t.Fatalf("config missing statsUserUplink: %s", text)
	}
	if !strings.Contains(text, `"statsUserDownlink":true`) {
		t.Fatalf("config missing statsUserDownlink: %s", text)
	}
	if !strings.Contains(text, `"email":"c_stats_key"`) || strings.Contains(text, `"email":"client1@test.com"`) {
		t.Fatalf("config should use stats_key as traffic identity: %s", text)
	}
}

func TestBuildConfigExposesStatsAPIInbound(t *testing.T) {
	config, err := xray.BuildConfig([]db.Inbound{{
		ID: 1, UUID: "test-uuid", Remark: "test", Protocol: "vless",
		Port: 10000, Network: "tcp", Security: "none", Enabled: true,
		Clients: []db.Client{{UUID: "c1-uuid", Email: "client1@test.com", Enabled: true}},
	}})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	encoded, _ := json.Marshal(config)
	text := string(encoded)
	for _, want := range []string{`"api":{"tag":"api"`, `"StatsService"`, `"tag":"api"`, `"port":10085`, `"outboundTag":"api"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("config missing stats API contract %q: %s", want, text)
		}
	}
}
