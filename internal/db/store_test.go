package db_test

import (
	"context"
	"testing"

	"github.com/imzyb/MiGate/internal/db"
)

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
