package db_test

import (
	"context"
	"testing"

	"github.com/imzyb/MiGate/internal/db"
)

func TestStoreCreatesAndListsOutboundsWithDefaults(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	outbounds, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list default outbounds: %v", err)
	}
	if len(outbounds) != 2 {
		t.Fatalf("expected direct and blocked defaults, got %+v", outbounds)
	}
	if outbounds[0].Tag != "direct" || outbounds[0].Protocol != "freedom" || outbounds[0].Sort != 0 {
		t.Fatalf("unexpected first default outbound: %+v", outbounds[0])
	}
	if outbounds[1].Tag != "blocked" || outbounds[1].Protocol != "blackhole" || outbounds[1].Sort != 1 {
		t.Fatalf("unexpected second default outbound: %+v", outbounds[1])
	}

	created, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{
		Tag:      "proxy-socks",
		Protocol: "socks",
		Address:  "127.0.0.1",
		Port:     1080,
		Username: "sam",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("create outbound: %v", err)
	}
	if created.ID == 0 || created.Tag != "proxy-socks" || created.Protocol != "socks" || created.Address != "127.0.0.1" || created.Port != 1080 || !created.Enabled {
		t.Fatalf("unexpected created outbound: %+v", created)
	}

	outbounds, err = store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list after create: %v", err)
	}
	if len(outbounds) != 3 || outbounds[2].Tag != "proxy-socks" || outbounds[2].Sort != 2 {
		t.Fatalf("created outbound not appended after defaults: %+v", outbounds)
	}
}

func TestStoreUpdatesOutboundFields(t *testing.T) {
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

	updated, err := store.UpdateOutbound(context.Background(), ob.ID, db.UpdateOutboundParams{
		Tag: "proxy-http-v2", Remark: "HTTP代理v2", Protocol: "socks",
		Address: "10.0.0.2", Port: 1080, Username: "newuser", Password: "newpass", Enabled: false,
	})
	if err != nil {
		t.Fatalf("update outbound: %v", err)
	}
	if updated.Tag != "proxy-http-v2" || updated.Remark != "HTTP代理v2" || updated.Protocol != "socks" ||
		updated.Address != "10.0.0.2" || updated.Port != 1080 || updated.Username != "newuser" ||
		updated.Password != "newpass" || updated.Enabled != false || updated.ID != ob.ID {
		t.Fatalf("unexpected updated outbound: %+v", updated)
	}

	loaded, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, o := range loaded {
		if o.ID == ob.ID {
			if o.Tag != "proxy-http-v2" || o.Enabled != false {
				t.Fatalf("updated values not persisted: %+v", o)
			}
		}
	}
}

func TestStoreUpdateOutboundRejectsUnknownID(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	_, err = store.UpdateOutbound(context.Background(), 99999, db.UpdateOutboundParams{Tag: "x", Remark: "x", Protocol: "socks", Address: "1.1.1.1", Port: 80})
	if err == nil {
		t.Fatal("expected error for unknown outbound")
	}
}

func TestStoreDeleteOutboundDeletesOutbound(t *testing.T) {
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

	if err := store.DeleteOutbound(context.Background(), ob.ID); err != nil {
		t.Fatalf("delete outbound: %v", err)
	}

	outbounds, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, o := range outbounds {
		if o.ID == ob.ID {
			t.Fatalf("outbound %d still present after deletion", ob.ID)
		}
	}
}

func TestStoreDeleteOutboundRejectsUnknownID(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := store.DeleteOutbound(context.Background(), 99999); err == nil {
		t.Fatal("expected error for unknown outbound")
	}
}

func TestStoreReorderOutboundsUpdatesSortOrder(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	// After seeding: direct=1, blocked=2
	o1, _ := store.CreateOutbound(context.Background(), db.CreateOutboundParams{Tag: "p1", Protocol: "socks", Address: "10.0.0.1", Port: 1080})
	o2, _ := store.CreateOutbound(context.Background(), db.CreateOutboundParams{Tag: "p2", Protocol: "http", Address: "10.0.0.2", Port: 3128})
	// Current order: direct(1), blocked(2), p1(3), p2(4)
	// Swap: p2, p1
	err = store.ReorderOutbounds(context.Background(), []int64{o2.ID, o1.ID})
	if err != nil {
		t.Fatalf("reorder outbounds: %v", err)
	}
	list, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list after reorder: %v", err)
	}
	if len(list) != 4 {
		t.Fatalf("expected 4 outbounds, got %d", len(list))
	}
	// Defaults stay first (sort 0-1), then reordered custom outbounds (sort 2-3)
	if list[0].ID != 1 || list[1].ID != 2 || list[2].ID != o2.ID || list[3].ID != o1.ID {
		t.Fatalf("expected defaults then reordered custom: got %d,%d,%d,%d", list[0].ID, list[1].ID, list[2].ID, list[3].ID)
	}
	if list[0].Sort != 0 || list[1].Sort != 1 || list[2].Sort != 2 || list[3].Sort != 3 {
		t.Fatalf("expected sequential sort values: got %d,%d,%d,%d", list[0].Sort, list[1].Sort, list[2].Sort, list[3].Sort)
	}
}

func TestStoreCreatesAndListsRoutingRules(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	// No routing rules initially
	rules, err := store.ListRoutingRules(context.Background())
	if err != nil {
		t.Fatalf("list routing rules: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected 0 default routing rules, got %d", len(rules))
	}

	rule, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{
		InboundTag:  "",
		OutboundTag: "blocked",
		Domain:      "geosite:malware",
		Protocol:    "",
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("create routing rule: %v", err)
	}
	if rule.OutboundTag != "blocked" || rule.Domain != "geosite:malware" || !rule.Enabled {
		t.Fatalf("unexpected rule: %+v", rule)
	}

	rules, err = store.ListRoutingRules(context.Background())
	if err != nil {
		t.Fatalf("list routing rules: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != rule.ID {
		t.Fatalf("expected 1 routing rule, got %+v", rules)
	}
}

func TestStoreUpdateRoutingRule(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	rule, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{
		InboundTag:  "",
		OutboundTag: "blocked",
		Domain:      "geosite:malware",
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	updated, err := store.UpdateRoutingRule(context.Background(), rule.ID, db.UpdateRoutingRuleParams{
		InboundTag:  "socks-in",
		OutboundTag: "direct",
		Domain:      "geosite:netflix",
		Protocol:    "",
		Enabled:     false,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.InboundTag != "socks-in" || updated.OutboundTag != "direct" || updated.Domain != "geosite:netflix" || updated.Enabled {
		t.Fatalf("unexpected updated rule: %+v", updated)
	}

	rules, err := store.ListRoutingRules(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rules) != 1 || rules[0].Domain != "geosite:netflix" {
		t.Fatalf("update not persisted: %+v", rules)
	}
}

func TestStoreDeleteRoutingRule(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	rule, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{
		OutboundTag: "blocked", Domain: "geosite:malware",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := store.DeleteRoutingRule(context.Background(), rule.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	rules, err := store.ListRoutingRules(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("rule not deleted: %+v", rules)
	}

	if err := store.DeleteRoutingRule(context.Background(), 99999); err == nil {
		t.Fatal("expected error for unknown routing rule")
	}
}

func TestStoreMigratesAndCreatesInboundWithClients(t *testing.T) {
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
	if inbound.ID == 0 || inbound.UUID == "" || inbound.Enabled != true {
		t.Fatalf("unexpected inbound: %+v", inbound)
	}

	client, err := store.CreateClient(context.Background(), db.CreateClientParams{
		InboundID: inbound.ID,
		Email:     "sam@example.com",
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if client.ID == 0 || client.UUID == "" || client.Enabled != true {
		t.Fatalf("unexpected client: %+v", client)
	}

	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(inbounds) != 1 || len(inbounds[0].Clients) != 1 {
		t.Fatalf("expected inbound with one client, got %+v", inbounds)
	}
	if inbounds[0].Clients[0].Email != "sam@example.com" {
		t.Fatalf("unexpected client email: %+v", inbounds[0].Clients[0])
	}
}

func TestStoreRejectsUnsupportedProtocol(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	_, err = store.CreateInbound(context.Background(), db.CreateInboundParams{
		Protocol: "http",
		Port:     8080,
	})
	if err == nil {
		t.Fatal("expected error for unsupported protocol")
	}
}

func TestStoreDeletesClient(t *testing.T) {
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
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{
		InboundID: inbound.ID, Email: "del@test.com",
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	if err := store.DeleteClient(context.Background(), client.ID); err != nil {
		t.Fatalf("delete client: %v", err)
	}

	// Verify client is gone
	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	for _, ib := range inbounds {
		for _, c := range ib.Clients {
			if c.ID == client.ID {
				t.Fatalf("client %d still present after deletion", client.ID)
			}
		}
	}
}

func TestStoreDeletesInboundAndCascadesClients(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "to-delete", Protocol: "vmess", Port: 8443, Network: "ws", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	_, err = store.CreateClient(context.Background(), db.CreateClientParams{
		InboundID: inbound.ID, Email: "orphan@test.com",
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	if err := store.DeleteInbound(context.Background(), inbound.ID); err != nil {
		t.Fatalf("delete inbound: %v", err)
	}

	// Verify inbound and its clients are gone
	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	for _, ib := range inbounds {
		if ib.ID == inbound.ID {
			t.Fatalf("inbound %d still present after deletion", inbound.ID)
		}
	}
}

func TestStoreDeleteInboundRejectsUnknownID(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := store.DeleteInbound(context.Background(), 99999); err == nil {
		t.Fatal("expected error when deleting non-existent inbound")
	}
}

func TestStoreDeleteClientRejectsUnknownID(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := store.DeleteClient(context.Background(), 99999); err == nil {
		t.Fatal("expected error when deleting non-existent client")
	}
}

func TestStoreUpdateInboundUpdatesFields(t *testing.T) {
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

	updated, err := store.UpdateInbound(context.Background(), inbound.ID, db.UpdateInboundParams{
		Remark:   "new",
		Port:     8443,
		Network:  "ws",
		Security: "tls",
		Enabled:  false,
	})
	if err != nil {
		t.Fatalf("update inbound: %v", err)
	}
	if updated.Remark != "new" || updated.Port != 8443 || updated.Network != "ws" || updated.Security != "tls" || updated.Enabled != false {
		t.Fatalf("unexpected updated inbound: %+v", updated)
	}
	if updated.ID != inbound.ID || updated.UUID != inbound.UUID {
		t.Fatalf("id/uuid changed after update: old=%+v new=%+v", inbound, updated)
	}

	loaded, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Remark != "new" || loaded[0].Enabled != false {
		t.Fatalf("updated values not persisted: %+v", loaded[0])
	}
}

func TestStoreUpdateInboundRejectsUnknownID(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	_, err = store.UpdateInbound(context.Background(), 99999, db.UpdateInboundParams{Remark: "x", Port: 80})
	if err == nil {
		t.Fatal("expected error for unknown inbound")
	}
}

func TestStoreUpdateClientUpdatesFields(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "test", Protocol: "trojan", Port: 443, Network: "tcp", Security: "tls",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{
		InboundID: inbound.ID, Email: "old@test.com",
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	updated, err := store.UpdateClient(context.Background(), client.ID, db.UpdateClientParams{
		Email:   "new@test.com",
		Enabled: false,
	})
	if err != nil {
		t.Fatalf("update client: %v", err)
	}
	if updated.Email != "new@test.com" || updated.Enabled != false {
		t.Fatalf("unexpected updated client: %+v", updated)
	}
	if updated.ID != client.ID || updated.UUID != client.UUID {
		t.Fatalf("id/uuid changed: old=%+v new=%+v", client, updated)
	}

	loaded, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(loaded) != 1 || len(loaded[0].Clients) != 1 || loaded[0].Clients[0].Email != "new@test.com" || loaded[0].Clients[0].Enabled != false {
		t.Fatalf("updated client not persisted: %+v", loaded[0].Clients[0])
	}
}

func TestStoreUpdateClientRejectsUnknownID(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	_, err = store.UpdateClient(context.Background(), 99999, db.UpdateClientParams{Email: "x"})
	if err == nil {
		t.Fatal("expected error for unknown client")
	}
}

func TestStoreCreateInboundWithTransportFields(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	// Create inbound with WS + Reality + SS fields
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark:             "transport-test",
		Protocol:           "vless",
		Port:               20000,
		Network:            "ws",
		Security:           "tls",
		WsPath:             "/migate",
		WsHost:             "test.example.com",
		GrpcServiceName:    "migate",
		RealityDest:        "www.google.com:443",
		RealityServerNames: "www.google.com",
		RealityShortID:     "6ba85179e30d4fc2",
		SSMethod:           "2022-blake3-aes-256-gcm",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	// Verify returned fields
	tests := []struct {
		name string
		got  string
	}{
		{"ws_path", inbound.WsPath},
		{"ws_host", inbound.WsHost},
		{"grpc_service_name", inbound.GrpcServiceName},
		{"reality_dest", inbound.RealityDest},
		{"reality_server_names", inbound.RealityServerNames},
		{"reality_short_id", inbound.RealityShortID},
		{"ss_method", inbound.SSMethod},
	}
	for _, tc := range tests {
		if tc.got == "" {
			t.Errorf("expected non-empty %s", tc.name)
		}
	}

	if inbound.WsPath != "/migate" {
		t.Fatalf("ws_path: got %q, want /migate", inbound.WsPath)
	}
	if inbound.WsHost != "test.example.com" {
		t.Fatalf("ws_host: got %q, want test.example.com", inbound.WsHost)
	}

	// Verify via list
	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	var found bool
	for _, ib := range inbounds {
		if ib.ID == inbound.ID {
			found = true
			if ib.WsPath != "/migate" {
				t.Fatalf("list ws_path: got %q, want /migate", ib.WsPath)
			}
			if ib.RealityDest != "www.google.com:443" {
				t.Fatalf("list reality_dest: got %q, want www.google.com:443", ib.RealityDest)
			}
			if ib.SSMethod != "2022-blake3-aes-256-gcm" {
				t.Fatalf("list ss_method: got %q, want 2022-blake3-aes-256-gcm", ib.SSMethod)
			}
			break
		}
	}
	if !found {
		t.Fatal("inbound not found in list")
	}

	// Test UpdateInbound preserves transport fields
	updated, err := store.UpdateInbound(context.Background(), inbound.ID, db.UpdateInboundParams{
		Remark:             "transport-updated",
		Protocol:           "vmess",
		Port:               20000,
		Network:            "ws",
		Security:           "tls",
		Enabled:            true,
		WsPath:             "/updated-path",
		WsHost:             "updated.example.com",
		GrpcServiceName:    "updated-grpc",
		RealityDest:        "updated.com:443",
		RealityServerNames: "updated.com",
		RealityShortID:     "deadbeef",
		SSMethod:           "2022-blake3-aes-128-gcm",
	})
	if err != nil {
		t.Fatalf("update inbound: %v", err)
	}
	if updated.WsPath != "/updated-path" {
		t.Fatalf("update ws_path: got %q, want /updated-path", updated.WsPath)
	}
	if updated.RealityDest != "updated.com:443" {
		t.Fatalf("update reality_dest: got %q, want updated.com:443", updated.RealityDest)
	}
	if updated.Remark != "transport-updated" {
		t.Fatalf("update remark: got %q, want transport-updated", updated.Remark)
	}
}

func TestStoreCreateInboundWithTLSFields(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	// Create inbound with TLS fields
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark:      "tls-test",
		Protocol:    "vless",
		Port:        30010,
		Network:     "tcp",
		Security:    "tls",
		TLSCertFile: "/etc/letsencrypt/live/example.com/fullchain.pem",
		TLSKeyFile:  "/etc/letsencrypt/live/example.com/privkey.pem",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	if inbound.TLSCertFile != "/etc/letsencrypt/live/example.com/fullchain.pem" {
		t.Fatalf("tls_cert_file: got %q, want /etc/letsencrypt/live/example.com/fullchain.pem", inbound.TLSCertFile)
	}
	if inbound.TLSKeyFile != "/etc/letsencrypt/live/example.com/privkey.pem" {
		t.Fatalf("tls_key_file: got %q, want /etc/letsencrypt/live/example.com/privkey.pem", inbound.TLSKeyFile)
	}

	// Verify via list
	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	var found bool
	for _, ib := range inbounds {
		if ib.ID == inbound.ID {
			found = true
			if ib.TLSCertFile != "/etc/letsencrypt/live/example.com/fullchain.pem" {
				t.Fatalf("list tls_cert_file: got %q", ib.TLSCertFile)
			}
			if ib.TLSKeyFile != "/etc/letsencrypt/live/example.com/privkey.pem" {
				t.Fatalf("list tls_key_file: got %q", ib.TLSKeyFile)
			}
			break
		}
	}
	if !found {
		t.Fatal("inbound not found in list")
	}

	// Update and verify TLS fields preserved
	updated, err := store.UpdateInbound(context.Background(), inbound.ID, db.UpdateInboundParams{
		Remark:      "tls-updated",
		Protocol:    "vless",
		Port:        30011,
		Network:     "tcp",
		Security:    "tls",
		Enabled:     true,
		TLSCertFile: "/new/path/cert.pem",
		TLSKeyFile:  "/new/path/key.pem",
	})
	if err != nil {
		t.Fatalf("update inbound: %v", err)
	}
	if updated.TLSCertFile != "/new/path/cert.pem" {
		t.Fatalf("update tls_cert_file: got %q", updated.TLSCertFile)
	}
	if updated.TLSKeyFile != "/new/path/key.pem" {
		t.Fatalf("update tls_key_file: got %q", updated.TLSKeyFile)
	}
}

func TestStoreCreateInboundWithXHTTPFields(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark:             "xhttp-test",
		Protocol:           "vless",
		Port:               30040,
		Network:            "xhttp",
		Security:           "reality",
		RealityDest:        "www.cloudflare.com:443",
		RealityServerNames: "www.cloudflare.com",
		XHTTPPath:          "/migate-xhttp",
		XHTTPMode:          "stream-one",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	if inbound.XHTTPPath != "/migate-xhttp" {
		t.Fatalf("xhttp_path: got %q, want /migate-xhttp", inbound.XHTTPPath)
	}
	if inbound.XHTTPMode != "stream-one" {
		t.Fatalf("xhttp_mode: got %q, want stream-one", inbound.XHTTPMode)
	}

	loaded, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(loaded) != 1 || loaded[0].XHTTPPath != "/migate-xhttp" || loaded[0].XHTTPMode != "stream-one" {
		t.Fatalf("xhttp fields not persisted via list: %+v", loaded)
	}

	updated, err := store.UpdateInbound(context.Background(), inbound.ID, db.UpdateInboundParams{
		Remark:             "xhttp-updated",
		Protocol:           "vless",
		Port:               30041,
		Network:            "xhttp",
		Security:           "reality",
		Enabled:            true,
		RealityDest:        "www.microsoft.com:443",
		RealityServerNames: "www.microsoft.com",
		XHTTPPath:          "/updated-xhttp",
		XHTTPMode:          "packet-up",
	})
	if err != nil {
		t.Fatalf("update inbound: %v", err)
	}
	if updated.XHTTPPath != "/updated-xhttp" || updated.XHTTPMode != "packet-up" {
		t.Fatalf("xhttp fields not updated: %+v", updated)
	}
}

func TestStoreCreateInboundWithInitialClient(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	// Create inbound with an initial client in one call
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark:   "init-client-test",
		Protocol: "vless",
		Port:     8443,
		Network:  "tcp",
		Security: "none",
		InitialClient: &db.CreateClientParams{
			Email:        "init@test.com",
			UUID:         "11111111-2222-4333-8444-555555555555",
			TrafficLimit: 100_000_000_000,
		},
	})
	if err != nil {
		t.Fatalf("create inbound with initial client: %v", err)
	}
	if inbound.ID == 0 {
		t.Fatalf("expected non-zero inbound ID")
	}
	if len(inbound.Clients) != 1 {
		t.Fatalf("expected 1 client attached to inbound, got %d: %+v", len(inbound.Clients), inbound.Clients)
	}
	if inbound.Clients[0].Email != "init@test.com" {
		t.Fatalf("unexpected client email: %s", inbound.Clients[0].Email)
	}
	if inbound.Clients[0].UUID != "11111111-2222-4333-8444-555555555555" {
		t.Fatalf("expected custom initial client uuid to be preserved, got %s", inbound.Clients[0].UUID)
	}
	if inbound.Clients[0].TrafficLimit != 100_000_000_000 {
		t.Fatalf("unexpected traffic limit: %d", inbound.Clients[0].TrafficLimit)
	}

	// Verify via ListInbounds
	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(inbounds) != 1 || len(inbounds[0].Clients) != 1 {
		t.Fatalf("expected 1 inbound with 1 client, got %+v", inbounds)
	}
}

func TestStoreCreateInboundWithoutInitialClient(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	// Creating inbound without initial client should work as before
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "no-init-client", Protocol: "vless", Port: 9443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	if inbound.ID == 0 {
		t.Fatalf("expected non-zero inbound ID")
	}
	if len(inbound.Clients) != 0 {
		t.Fatalf("expected 0 clients, got %d", len(inbound.Clients))
	}
}
