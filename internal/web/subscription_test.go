package web

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/imzyb/MiGate/internal/db"
)

func TestShareLinkGeneratorsMatchInboundCapabilities(t *testing.T) {
	for _, capability := range db.InboundCapabilities() {
		_, hasGenerator := shareLinkGenerators[capability.Protocol]
		if hasGenerator != capability.ShareLink {
			t.Fatalf("protocol %s share generator = %v, want share_link %v", capability.Protocol, hasGenerator, capability.ShareLink)
		}
	}
}

func TestShareLinkRejectsUnsupportedCapabilityProtocols(t *testing.T) {
	for _, capability := range db.InboundCapabilities() {
		if capability.ShareLink {
			continue
		}
		_, err := shareLink("panel.example.com", db.Inbound{Protocol: capability.Protocol, Port: 1080}, db.Client{})
		if err == nil {
			t.Fatalf("protocol %s should be rejected by subscription share link", capability.Protocol)
		}
	}
}

func TestUserPasswordInboundShareLinks(t *testing.T) {
	for _, tc := range []struct {
		protocol string
		want     string
	}{
		{protocol: "socks", want: "socks://user-1:p%40ss%3Aword@proxy.example.com:20001#phone+1"},
		{protocol: "http", want: "http://user-1:p%40ss%3Aword@proxy.example.com:20001#phone+1"},
	} {
		t.Run(tc.protocol, func(t *testing.T) {
			link, err := shareLink("proxy.example.com", db.Inbound{
				Protocol: tc.protocol,
				Port:     20001,
				Network:  "tcp",
				Security: "none",
			}, db.Client{Email: "phone 1", CredentialID: "user-1", Password: "p@ss:word"})
			if err != nil {
				t.Fatalf("share link: %v", err)
			}
			if link != tc.want {
				t.Fatalf("link = %q, want %q", link, tc.want)
			}
		})
	}
}

func TestVMessTLSShareLinkUsesTLSSNIAsEndpointWhenCertificateAttached(t *testing.T) {
	link, err := shareLink("103.193.149.217", db.Inbound{
		Protocol:    "vmess",
		Port:        20001,
		Network:     "ws",
		Security:    "tls",
		WsPath:      "/ray",
		TLSSNI:      "hkcm.example.kg",
		TLSCertFile: "/etc/migate/certs/hkcm.example.kg/fullchain.pem",
		TLSKeyFile:  "/etc/migate/certs/hkcm.example.kg/privkey.key",
	}, db.Client{Email: "phone", UUID: "11111111-1111-4111-8111-111111111111"})
	if err != nil {
		t.Fatalf("share link: %v", err)
	}
	if len(link) <= len("vmess://") {
		t.Fatalf("unexpected vmess link: %q", link)
	}
	payload, err := base64.StdEncoding.DecodeString(link[len("vmess://"):])
	if err != nil {
		t.Fatalf("decode vmess payload: %v", err)
	}
	var data map[string]string
	if err := json.Unmarshal(payload, &data); err != nil {
		t.Fatalf("unmarshal vmess payload: %v", err)
	}
	if data["add"] != "hkcm.example.kg" || data["sni"] != "hkcm.example.kg" {
		t.Fatalf("vmess TLS endpoint should use SNI domain, got payload %#v", data)
	}
}

func TestVMessTLSWSShareLinkUsesSynchronizedWSHost(t *testing.T) {
	link, err := shareLink("103.193.149.217", db.Inbound{
		Protocol:    "vmess",
		Port:        20001,
		Network:     "ws",
		Security:    "tls",
		WsPath:      "/ray",
		WsHost:      "hkcm.example.kg",
		TLSSNI:      "hkcm.example.kg",
		TLSCertFile: "/etc/migate/certs/hkcm.example.kg/fullchain.pem",
		TLSKeyFile:  "/etc/migate/certs/hkcm.example.kg/privkey.key",
	}, db.Client{Email: "phone", UUID: "11111111-1111-4111-8111-111111111111"})
	if err != nil {
		t.Fatalf("share link: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(link[len("vmess://"):])
	if err != nil {
		t.Fatalf("decode vmess payload: %v", err)
	}
	var data map[string]string
	if err := json.Unmarshal(payload, &data); err != nil {
		t.Fatalf("unmarshal vmess payload: %v", err)
	}
	if data["add"] != "hkcm.example.kg" || data["host"] != "hkcm.example.kg" {
		t.Fatalf("vmess TLS WS link should use synchronized certificate domain, got payload %#v", data)
	}
	if data["host"] == "example.com" {
		t.Fatalf("vmess TLS WS host should not keep template default, got payload %#v", data)
	}
}

func TestHysteria2ShareLinkKeepsSelfSignedCertificateCompatibility(t *testing.T) {
	link, err := shareLink("vpn.example.com", db.Inbound{
		Protocol:        "hysteria2",
		Port:            20001,
		Hy2UpMbps:       80,
		Hy2DownMbps:     120,
		Hy2Obfs:         "salamander",
		Hy2ObfsPassword: "obfs-secret",
		TLSSNI:          "migate",
	}, db.Client{Email: "hy2@example.com", Password: "hy2-secret"})
	if err != nil {
		t.Fatalf("share link: %v", err)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse link %q: %v", link, err)
	}
	if parsed.Scheme != "hysteria2" || parsed.Hostname() != "vpn.example.com" || parsed.Port() != "20001" {
		t.Fatalf("unexpected hy2 endpoint: %s", link)
	}
	if got, _ := parsed.User.Password(); got != "" {
		t.Fatalf("hysteria2 should use password as username, got password part %q", got)
	}
	if parsed.User.Username() != "hy2-secret" {
		t.Fatalf("unexpected hy2 password credential: %q", parsed.User.Username())
	}
	q := parsed.Query()
	for key, want := range map[string]string{
		"up_mbps":       "80",
		"down_mbps":     "120",
		"obfs":          "salamander",
		"obfs-password": "obfs-secret",
		"security":      "tls",
		"sni":           "migate",
		"insecure":      "1",
	} {
		if got := q.Get(key); got != want {
			t.Fatalf("hy2 query %s = %q, want %q in %s", key, got, want, link)
		}
	}
}

func TestTUICShareLinkKeepsSelfSignedCertificateCompatibility(t *testing.T) {
	link, err := shareLink("vpn.example.com", db.Inbound{
		Protocol:              "tuic",
		Port:                  20002,
		TLSSNI:                "migate",
		TuicCongestionControl: "cubic",
		TuicZeroRTT:           true,
	}, db.Client{Email: "tuic@example.com", CredentialID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Password: "tuic-secret"})
	if err != nil {
		t.Fatalf("share link: %v", err)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse link %q: %v", link, err)
	}
	if parsed.Scheme != "tuic" || parsed.Hostname() != "vpn.example.com" || parsed.Port() != "20002" {
		t.Fatalf("unexpected tuic endpoint: %s", link)
	}
	password, hasPassword := parsed.User.Password()
	if parsed.User.Username() != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" || !hasPassword || password != "tuic-secret" {
		t.Fatalf("unexpected tuic credentials: user=%q password=%q has=%v", parsed.User.Username(), password, hasPassword)
	}
	q := parsed.Query()
	for key, want := range map[string]string{
		"sni":                "migate",
		"congestion_control": "cubic",
		"zero_rtt_handshake": "1",
		"insecure":           "1",
	} {
		if got := q.Get(key); got != want {
			t.Fatalf("tuic query %s = %q, want %q in %s", key, got, want, link)
		}
	}
}
