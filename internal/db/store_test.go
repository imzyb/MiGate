package db_test

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/imzyb/MiGate/internal/db"
	_ "modernc.org/sqlite"
)

func join(parts ...string) string { return strings.Join(parts, "") }

func mustListOutboundsDB(t *testing.T, store *db.Store) []db.Outbound {
	t.Helper()
	outbounds, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list outbounds: %v", err)
	}
	return outbounds
}

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
	if len(outbounds) != 3 {
		t.Fatalf("expected direct, blocked and dns defaults, got %+v", outbounds)
	}
	if outbounds[0].Tag != "direct" || outbounds[0].Protocol != "freedom" || outbounds[0].Sort != 0 {
		t.Fatalf("unexpected first default outbound: %+v", outbounds[0])
	}
	if outbounds[1].Tag != "blocked" || outbounds[1].Protocol != "blackhole" || outbounds[1].Sort != 1 {
		t.Fatalf("unexpected second default outbound: %+v", outbounds[1])
	}
	if outbounds[2].Tag != "dns" || outbounds[2].Protocol != "dns" || outbounds[2].Sort != 2 {
		t.Fatalf("unexpected third default outbound: %+v", outbounds[2])
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
	if len(outbounds) != 4 || outbounds[3].Tag != "proxy-socks" || outbounds[3].Sort != 3 {
		t.Fatalf("created outbound not appended after defaults: %+v", outbounds)
	}
	if outbounds[3].LastSeenAt != created.LastSeenAt {
		t.Fatalf("returned last_seen_at should match persisted value: created=%q listed=%q", created.LastSeenAt, outbounds[3].LastSeenAt)
	}
}

func TestCreateOutboundRejectsSubscriptionSourceOutsideMaterialization(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{
		Tag: "fake-sub", Protocol: "socks", Address: "127.0.0.1", Port: 1080, Source: db.OutboundSourceSubscription, SubscriptionID: 123, SubscriptionIdentity: "fake",
	}); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("expected reserved source error, got %v", err)
	}
	created, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{
		Tag: "pool-socks-us", Protocol: "socks", Address: "127.0.0.1", Port: 1080, Source: db.OutboundSourceProxyPool, SubscriptionID: 123, SubscriptionIdentity: "fake", RawLink: "trojan://fake",
	})
	if err != nil {
		t.Fatalf("proxy pool source should remain allowed: %v", err)
	}
	if created.Source != db.OutboundSourceProxyPool {
		t.Fatalf("expected proxy_pool source, got %+v", created)
	}
	if created.SubscriptionID != 0 || created.SubscriptionIdentity != "" || created.RawLink != "" {
		t.Fatalf("non-subscription source should not keep subscription metadata: %+v", created)
	}
}

func TestStoreMaterializesSubscriptionOutboundsAndDisablesMissing(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	sub, err := store.CreateOutboundSubscription(context.Background(), db.CreateOutboundSubscriptionParams{
		Remark: "sub", URL: "https://example.com/sub", TagPrefix: "sub1-", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	nodes := []db.MaterializedSubscriptionOutbound{
		{Tag: "sub1-a", Remark: "a", Protocol: "trojan", Address: "example.com", Port: 443, Password: "pw", SubscriptionIdentity: "a", RawLink: "trojan://pw@example.com:443#a", Position: 0},
		{Tag: "sub1-b", Remark: "b", Protocol: "shadowsocks", Address: "example.net", Port: 8388, Username: "aes-128-gcm", Password: "pw", SubscriptionIdentity: "b", RawLink: "ss://x", Position: 1},
	}
	if _, err := store.MaterializeSubscriptionOutbounds(context.Background(), sub.ID, nodes, []string{"a", "b"}); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	outbounds, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list outbounds: %v", err)
	}
	var firstID int64
	for _, outbound := range outbounds {
		if outbound.SubscriptionIdentity == "a" {
			firstID = outbound.ID
		}
	}
	if firstID == 0 {
		t.Fatalf("expected materialized outbound a in %+v", outbounds)
	}
	if _, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{OutboundID: firstID, Enabled: true}); err != nil {
		t.Fatalf("create route to subscription outbound: %v", err)
	}
	if _, err := store.MaterializeSubscriptionOutbounds(context.Background(), sub.ID, nodes[1:], []string{"b"}); err != nil {
		t.Fatalf("materialize second: %v", err)
	}
	outbounds, _ = store.ListOutbounds(context.Background())
	foundDisabled := false
	for _, outbound := range outbounds {
		if outbound.ID == firstID {
			foundDisabled = !outbound.Enabled
		}
	}
	if !foundDisabled {
		t.Fatalf("expected missing subscription node to be disabled, got %+v", outbounds)
	}
	rules, err := store.ListRoutingRules(context.Background())
	if err != nil || len(rules) != 1 || rules[0].OutboundID != firstID {
		t.Fatalf("routing rule should remain intact, rules=%+v err=%v", rules, err)
	}
}

func TestStoreUsesDefaultOutboundSubscriptionUpdateInterval(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	sub, err := store.CreateOutboundSubscription(context.Background(), db.CreateOutboundSubscriptionParams{
		Remark: "default interval", URL: "https://example.com/sub", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	if sub.UpdateIntervalSeconds != db.DefaultOutboundSubscriptionUpdateIntervalSeconds {
		t.Fatalf("expected default interval %d, got %+v", db.DefaultOutboundSubscriptionUpdateIntervalSeconds, sub)
	}
	updated, err := store.UpdateOutboundSubscription(context.Background(), sub.ID, db.UpdateOutboundSubscriptionParams{
		Remark: "default interval", URL: "https://example.com/sub", Enabled: true,
	})
	if err != nil {
		t.Fatalf("update subscription: %v", err)
	}
	if updated.UpdateIntervalSeconds != db.DefaultOutboundSubscriptionUpdateIntervalSeconds {
		t.Fatalf("expected updated default interval %d, got %+v", db.DefaultOutboundSubscriptionUpdateIntervalSeconds, updated)
	}
}

func TestUpdateOutboundSubscriptionDisabledDisablesMaterializedNodes(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	sub, err := store.CreateOutboundSubscription(context.Background(), db.CreateOutboundSubscriptionParams{
		Remark: "sub", URL: "https://example.com/sub", TagPrefix: "sub1-", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	if _, err := store.MaterializeSubscriptionOutbounds(context.Background(), sub.ID, []db.MaterializedSubscriptionOutbound{
		{Tag: "sub1-a", Remark: "a", Protocol: "trojan", Address: "example.com", Port: 443, Password: "pw", SubscriptionIdentity: "a", RawLink: "trojan://pw@example.com:443#a", Position: 0},
	}, []string{"a"}); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if _, err := store.UpdateOutboundSubscription(context.Background(), sub.ID, db.UpdateOutboundSubscriptionParams{
		Remark: "sub", URL: "https://example.com/sub", TagPrefix: "sub1-", Enabled: false,
	}); err != nil {
		t.Fatalf("disable subscription: %v", err)
	}
	outbounds, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list outbounds: %v", err)
	}
	for _, outbound := range outbounds {
		if outbound.SubscriptionID == sub.ID && outbound.Enabled {
			t.Fatalf("disabled subscription should disable materialized node: %+v", outbound)
		}
	}
}

func TestMaterializeSubscriptionOutboundsRejectsDisabledSubscription(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	sub, err := store.CreateOutboundSubscription(context.Background(), db.CreateOutboundSubscriptionParams{
		Remark: "sub", URL: "https://example.com/sub", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	if _, err := store.UpdateOutboundSubscription(context.Background(), sub.ID, db.UpdateOutboundSubscriptionParams{
		Remark: "sub", URL: "https://example.com/sub", Enabled: false,
	}); err != nil {
		t.Fatalf("disable subscription: %v", err)
	}
	_, err = store.MaterializeSubscriptionOutbounds(context.Background(), sub.ID, []db.MaterializedSubscriptionOutbound{
		{Tag: "sub1-a", Remark: "a", Protocol: "trojan", Address: "example.com", Port: 443, Password: "pw", SubscriptionIdentity: "a", Position: 0},
	}, []string{"a"})
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected disabled subscription materialize error, got %v", err)
	}
}

func TestMarkOutboundSubscriptionFetchFailureKeepsIdentitiesAndLastFetched(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	sub, err := store.CreateOutboundSubscription(context.Background(), db.CreateOutboundSubscriptionParams{
		Remark: "sub", URL: "https://example.com/sub", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	firstFetched := time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)
	if err := store.MarkOutboundSubscriptionFetch(context.Background(), sub.ID, firstFetched, "", []string{"stable-a"}); err != nil {
		t.Fatalf("mark success: %v", err)
	}
	if err := store.MarkOutboundSubscriptionFetch(context.Background(), sub.ID, firstFetched.Add(time.Hour), "upstream failed", nil); err != nil {
		t.Fatalf("mark failure: %v", err)
	}
	loaded, ok, err := store.GetOutboundSubscription(context.Background(), sub.ID)
	if err != nil || !ok {
		t.Fatalf("get subscription: ok=%v err=%v", ok, err)
	}
	if loaded.LinkIdentitiesJSON != `["stable-a"]` {
		t.Fatalf("failure should keep identities, got %q", loaded.LinkIdentitiesJSON)
	}
	if loaded.LastFetchedAt != firstFetched.Format(time.RFC3339) {
		t.Fatalf("failure should keep last_fetched_at, got %q", loaded.LastFetchedAt)
	}
	if loaded.LastAttemptAt == "" || loaded.LastError != "upstream failed" {
		t.Fatalf("failure should record attempt and error, got %+v", loaded)
	}
}

func TestUpdateOutboundProtectsSubscriptionConnectionFields(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	sub, err := store.CreateOutboundSubscription(context.Background(), db.CreateOutboundSubscriptionParams{
		Remark: "sub", URL: "https://example.com/sub", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	if _, err := store.MaterializeSubscriptionOutbounds(context.Background(), sub.ID, []db.MaterializedSubscriptionOutbound{
		{Tag: "sub1-a", Remark: "a", Protocol: "trojan", Address: "example.com", Port: 443, Password: "pw", SubscriptionIdentity: "a", RawLink: "trojan://pw@example.com:443#a", SettingsJSON: `{"tls":true}`, Position: 0},
	}, []string{"a"}); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	var target db.Outbound
	for _, outbound := range mustListOutboundsDB(t, store) {
		if outbound.SubscriptionID == sub.ID {
			target = outbound
		}
	}
	updated, err := store.UpdateOutbound(context.Background(), target.ID, db.UpdateOutboundParams{
		Tag: "changed", Remark: "manual remark", Protocol: "socks", Address: "127.0.0.1", Port: 1080, Username: "user", Password: "secret", Enabled: false, SettingsJSON: `{"security":"none"}`,
	})
	if err != nil {
		t.Fatalf("update subscription outbound: %v", err)
	}
	if updated.Tag != target.Tag || updated.Protocol != target.Protocol || updated.Address != target.Address || updated.Port != target.Port || updated.Password != target.Password || updated.SettingsJSON != target.SettingsJSON {
		t.Fatalf("subscription connection fields should be preserved, before=%+v after=%+v", target, updated)
	}
	if updated.Remark != "manual remark" || updated.Enabled {
		t.Fatalf("subscription editable fields not applied: %+v", updated)
	}
}

func TestUpdateOutboundRejectsEnablingDisabledSubscriptionNode(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	sub, err := store.CreateOutboundSubscription(context.Background(), db.CreateOutboundSubscriptionParams{
		Remark: "sub", URL: "https://example.com/sub", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	if _, err := store.MaterializeSubscriptionOutbounds(context.Background(), sub.ID, []db.MaterializedSubscriptionOutbound{
		{Tag: "sub1-a", Remark: "a", Protocol: "trojan", Address: "example.com", Port: 443, Password: "pw", SubscriptionIdentity: "a", RawLink: "trojan://pw@example.com:443#a", Position: 0},
	}, []string{"a"}); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	var target db.Outbound
	for _, outbound := range mustListOutboundsDB(t, store) {
		if outbound.SubscriptionID == sub.ID {
			target = outbound
		}
	}
	if _, err := store.UpdateOutboundSubscription(context.Background(), sub.ID, db.UpdateOutboundSubscriptionParams{
		Remark: "sub", URL: "https://example.com/sub", Enabled: false,
	}); err != nil {
		t.Fatalf("disable subscription: %v", err)
	}
	_, err = store.UpdateOutbound(context.Background(), target.ID, db.UpdateOutboundParams{
		Tag: target.Tag, Remark: target.Remark, Protocol: target.Protocol, Address: target.Address, Port: target.Port, Password: target.Password, Enabled: true,
	})
	if err == nil || !strings.Contains(err.Error(), "subscription_disabled") {
		t.Fatalf("expected subscription_disabled, got %v", err)
	}
	for _, outbound := range mustListOutboundsDB(t, store) {
		if outbound.ID == target.ID && outbound.Enabled {
			t.Fatalf("disabled subscription node should remain disabled: %+v", outbound)
		}
	}
}

func TestSetOutboundEnabledRejectsEnablingDisabledSubscriptionNode(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	sub, err := store.CreateOutboundSubscription(context.Background(), db.CreateOutboundSubscriptionParams{
		Remark: "sub", URL: "https://example.com/sub", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	if _, err := store.MaterializeSubscriptionOutbounds(context.Background(), sub.ID, []db.MaterializedSubscriptionOutbound{
		{Tag: "sub1-a", Remark: "a", Protocol: "trojan", Address: "example.com", Port: 443, Password: "pw", SubscriptionIdentity: "a", Position: 0},
	}, []string{"a"}); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	var target db.Outbound
	for _, outbound := range mustListOutboundsDB(t, store) {
		if outbound.SubscriptionID == sub.ID {
			target = outbound
		}
	}
	if _, err := store.UpdateOutboundSubscription(context.Background(), sub.ID, db.UpdateOutboundSubscriptionParams{
		Remark: "sub", URL: "https://example.com/sub", Enabled: false,
	}); err != nil {
		t.Fatalf("disable subscription: %v", err)
	}
	_, err = store.SetOutboundEnabled(context.Background(), target.ID, true)
	if err == nil || !strings.Contains(err.Error(), "subscription_disabled") {
		t.Fatalf("expected subscription_disabled, got %v", err)
	}
	for _, outbound := range mustListOutboundsDB(t, store) {
		if outbound.ID == target.ID && outbound.Enabled {
			t.Fatalf("disabled subscription node should remain disabled: %+v", outbound)
		}
	}
}

func TestStoreSoftDeletesOutboundSubscriptionWithoutOrphaningNodes(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	sub, err := store.CreateOutboundSubscription(context.Background(), db.CreateOutboundSubscriptionParams{
		Remark: "sub", URL: "https://example.com/sub", TagPrefix: "sub1-", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	if _, err := store.MaterializeSubscriptionOutbounds(context.Background(), sub.ID, []db.MaterializedSubscriptionOutbound{
		{Tag: "sub1-a", Remark: "a", Protocol: "trojan", Address: "example.com", Port: 443, Password: "pw", SubscriptionIdentity: "a", RawLink: "trojan://pw@example.com:443#a", Position: 0},
	}, []string{"a"}); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if err := store.DeleteOutboundSubscription(context.Background(), sub.ID); err != nil {
		t.Fatalf("delete subscription: %v", err)
	}
	subs, err := store.ListOutboundSubscriptions(context.Background())
	if err != nil {
		t.Fatalf("list subscriptions: %v", err)
	}
	if len(subs) != 0 {
		t.Fatalf("soft-deleted subscription should be hidden, got %+v", subs)
	}
	outbounds, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list outbounds: %v", err)
	}
	for _, outbound := range outbounds {
		if outbound.SubscriptionIdentity == "a" {
			if outbound.SubscriptionID != sub.ID || outbound.Source != db.OutboundSourceSubscription || outbound.Enabled {
				t.Fatalf("subscription node should remain attributed and disabled, got %+v", outbound)
			}
			return
		}
	}
	t.Fatalf("expected subscription outbound to remain after soft delete, got %+v", outbounds)
}

func TestStoreRejectsWritesToSoftDeletedOutboundSubscription(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	sub, err := store.CreateOutboundSubscription(context.Background(), db.CreateOutboundSubscriptionParams{
		Remark: "sub", URL: "https://example.com/sub", TagPrefix: "sub1-", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	if err := store.DeleteOutboundSubscription(context.Background(), sub.ID); err != nil {
		t.Fatalf("delete subscription: %v", err)
	}
	if _, err := store.UpdateOutboundSubscription(context.Background(), sub.ID, db.UpdateOutboundSubscriptionParams{
		Remark: "updated", URL: "https://example.com/next", Enabled: true,
	}); err == nil {
		t.Fatal("expected update of soft-deleted subscription to fail")
	}
	if err := store.MarkOutboundSubscriptionFetch(context.Background(), sub.ID, time.Now(), "", []string{"a"}); err == nil {
		t.Fatal("expected fetch mark for soft-deleted subscription to fail")
	}
	if _, err := store.MaterializeSubscriptionOutbounds(context.Background(), sub.ID, []db.MaterializedSubscriptionOutbound{
		{Tag: "sub1-a", Remark: "a", Protocol: "trojan", Address: "example.com", Port: 443, Password: "pw", SubscriptionIdentity: "a", Position: 0},
	}, []string{"a"}); err == nil {
		t.Fatal("expected materialize for soft-deleted subscription to fail")
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
		Address: "10.0.0.2", Port: 1080, Username: "newuser", Password: "newpass", Enabled: false, SettingsJSON: `{"security":"tls"}`,
	})
	if err != nil {
		t.Fatalf("update outbound: %v", err)
	}
	if updated.Tag != "proxy-http-v2" || updated.Remark != "HTTP代理v2" || updated.Protocol != "socks" ||
		updated.Address != "10.0.0.2" || updated.Port != 1080 || updated.Username != "newuser" ||
		updated.Password != "newpass" || updated.Enabled != false || updated.ID != ob.ID || updated.SettingsJSON == "" {
		t.Fatalf("unexpected updated outbound: %+v", updated)
	}
	cleared, err := store.UpdateOutbound(context.Background(), ob.ID, db.UpdateOutboundParams{
		Tag: "proxy-http-v2", Remark: "HTTP代理v2", Protocol: "socks",
		Address: "10.0.0.2", Port: 1080, Username: "newuser", Password: "newpass", Enabled: false, SettingsJSON: "",
	})
	if err != nil {
		t.Fatalf("clear outbound settings_json: %v", err)
	}
	if cleared.SettingsJSON != "" {
		t.Fatalf("expected settings_json to be cleared, got %+v", cleared)
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

func TestStoreInfersInboundCoreByProtocol(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	cases := []struct {
		protocol string
		core     string
	}{
		{"hysteria2", db.CoreSingbox},
		{"tuic", db.CoreSingbox},
		{"shadowtls", db.CoreSingbox},
		{"vless", db.CoreXray},
		{"vmess", db.CoreXray},
		{"trojan", db.CoreXray},
		{"shadowsocks", db.CoreXray},
		{"http", db.CoreXray},
		{"socks", db.CoreXray},
	}
	for i, tc := range cases {
		network := "tcp"
		security := "none"
		if tc.protocol == "hysteria2" || tc.protocol == "tuic" {
			network = "udp"
			security = "tls"
		}
		tlsSNI := ""
		if tc.protocol == "shadowtls" {
			tlsSNI = "www.example.com"
		}
		inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
			Remark: fmt.Sprintf("in-%s", tc.protocol), Protocol: tc.protocol, Port: 22000 + i, Network: network, Security: security, TLSSNI: tlsSNI,
		})
		if err != nil {
			t.Fatalf("create %s inbound: %v", tc.protocol, err)
		}
		if inbound.Core != tc.core {
			t.Fatalf("%s expected core %s, got %+v", tc.protocol, tc.core, inbound)
		}
	}
}

func TestStoreInfersOutboundSupportedCores(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	sharedProtocols := []string{"socks", "http", "vless"}
	for i, protocol := range sharedProtocols {
		params := db.CreateOutboundParams{Tag: "shared-" + protocol, Protocol: protocol, Address: "127.0.0.1", Port: 10000 + i, Password: "secret"}
		if protocol == "vless" {
			params.Username = "11111111-1111-4111-8111-111111111111"
		}
		outbound, err := store.CreateOutbound(context.Background(), params)
		if err != nil {
			t.Fatalf("create shared outbound %s: %v", protocol, err)
		}
		if !db.SupportsCore(outbound.SupportedCores, db.CoreXray) || !db.SupportsCore(outbound.SupportedCores, db.CoreSingbox) {
			t.Fatalf("expected shared cores for %s, got %+v", protocol, outbound.SupportedCores)
		}
	}
	for i, protocol := range []string{"hysteria2", "tuic", "shadowtls"} {
		params := db.CreateOutboundParams{Tag: "sb-" + protocol, Protocol: protocol, Address: "127.0.0.1", Port: 11000 + i, Password: "secret"}
		if protocol == "tuic" {
			params.Username = "11111111-1111-4111-8111-111111111111"
		}
		outbound, err := store.CreateOutbound(context.Background(), params)
		if err != nil {
			t.Fatalf("create sing-box outbound %s: %v", protocol, err)
		}
		if db.SupportsCore(outbound.SupportedCores, db.CoreXray) || !db.SupportsCore(outbound.SupportedCores, db.CoreSingbox) {
			t.Fatalf("expected sing-box only cores for %s, got %+v", protocol, outbound.SupportedCores)
		}
	}
}

func TestStoreDoesNotPersistOutboundSupportedCores(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	columns := store.TableColumnsForTest(t, "outbounds")
	for _, column := range columns {
		if column.Name == "supported_cores" {
			t.Fatalf("supported_cores should not be persisted in outbounds schema: %+v", columns)
		}
	}

	outbound, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{Tag: "schema-socks", Protocol: "socks", Address: "127.0.0.1", Port: 1080})
	if err != nil {
		t.Fatalf("create outbound: %v", err)
	}
	if !db.SupportsCore(outbound.SupportedCores, db.CoreXray) || !db.SupportsCore(outbound.SupportedCores, db.CoreSingbox) {
		t.Fatalf("expected API output supported_cores to be inferred, got %+v", outbound.SupportedCores)
	}
	singboxInbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "sb-in", Protocol: "hysteria2", Port: 23012, Network: "udp", Security: "tls"})
	if err != nil {
		t.Fatalf("create sing-box inbound: %v", err)
	}
	if _, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{InboundTag: db.GeneratedInboundTag(singboxInbound), OutboundID: outbound.ID, Enabled: true}); err != nil {
		t.Fatalf("expected sing-box inbound to route to protocol-derived shared socks outbound: %v", err)
	}
}

func TestOutboundProtocolSupportLevelDocumentsBoundaries(t *testing.T) {
	cases := []struct {
		protocol string
		level    string
		cores    []string
	}{
		{"freedom", db.OutboundSupportBuiltin, []string{db.CoreXray, db.CoreSingbox}},
		{"blackhole", db.OutboundSupportBuiltin, []string{db.CoreXray, db.CoreSingbox}},
		{"dns", db.OutboundSupportBuiltin, []string{db.CoreXray, db.CoreSingbox}},
		{"direct", db.OutboundSupportBuiltin, []string{db.CoreXray, db.CoreSingbox}},
		{"block", db.OutboundSupportBuiltin, []string{db.CoreXray, db.CoreSingbox}},
		{"socks", db.OutboundSupportFull, []string{db.CoreXray, db.CoreSingbox}},
		{"socks5", db.OutboundSupportFull, []string{db.CoreXray, db.CoreSingbox}},
		{"http", db.OutboundSupportFull, []string{db.CoreXray, db.CoreSingbox}},
		{"https", db.OutboundSupportFull, []string{db.CoreXray, db.CoreSingbox}},
		{"vless", db.OutboundSupportBasic, []string{db.CoreXray, db.CoreSingbox}},
		{"trojan", db.OutboundSupportBasic, []string{db.CoreXray, db.CoreSingbox}},
		{"shadowsocks", db.OutboundSupportBasic, []string{db.CoreXray, db.CoreSingbox}},
		{"hysteria2", db.OutboundSupportBasic, []string{db.CoreSingbox}},
		{"tuic", db.OutboundSupportBasic, []string{db.CoreSingbox}},
		{"shadowtls", db.OutboundSupportBasic, []string{db.CoreSingbox}},
		{"unknown", db.OutboundSupportNone, []string{}},
	}
	for _, tc := range cases {
		if got := db.OutboundProtocolSupportLevel(tc.protocol); got != tc.level {
			t.Fatalf("expected %s support level %s, got %s", tc.protocol, tc.level, got)
		}
		gotCores := db.OutboundProtocolSupportedCores(tc.protocol)
		if len(gotCores) != len(tc.cores) {
			t.Fatalf("expected %s cores %+v, got %+v", tc.protocol, tc.cores, gotCores)
		}
		for i := range gotCores {
			if gotCores[i] != tc.cores[i] {
				t.Fatalf("expected %s cores %+v, got %+v", tc.protocol, tc.cores, gotCores)
			}
		}
	}
}

func TestGeneratedOutboundTagMapsBackToOutboundProfile(t *testing.T) {
	for _, tc := range []struct {
		core string
		tag  string
	}{
		{db.CoreXray, db.GeneratedOutboundTag(db.CoreXray, 42, "proxy")},
		{db.CoreSingbox, db.GeneratedOutboundTag(db.CoreSingbox, 42, "proxy")},
	} {
		id, ok := db.OutboundProfileIDFromGeneratedTag(tc.core, tc.tag)
		if !ok || id != 42 {
			t.Fatalf("expected %s generated tag %q to map to profile 42, got id=%d ok=%v", tc.core, tc.tag, id, ok)
		}
	}
	if _, ok := db.OutboundProfileIDFromGeneratedTag(db.CoreXray, "direct"); ok {
		t.Fatal("logical direct tag should not parse as generated outbound profile tag")
	}
	if _, ok := db.OutboundProfileIDFromGeneratedTag(db.CoreXray, "xray-out-42-extra"); ok {
		t.Fatal("generated outbound tag parser should reject trailing garbage")
	}
}

func TestRoutingRuleOutboundResolutionRequiresID(t *testing.T) {
	outbounds := []db.Outbound{
		{ID: 1, Tag: "old-tag", Protocol: "hysteria2", Enabled: true},
		{ID: 42, Tag: "new-tag", Protocol: "socks", Enabled: true},
	}
	rule := db.RoutingRule{OutboundID: 42, OutboundTag: "old-tag"}
	outbound, ok := db.ResolveRuleOutbound(rule, outbounds)
	if !ok || outbound.ID != 42 {
		t.Fatalf("expected outbound_id to resolve target, got outbound=%+v ok=%v", outbound, ok)
	}
	if got := db.EffectiveRuleOutboundID(rule, outbounds); got != 42 {
		t.Fatalf("expected effective outbound id 42, got %d", got)
	}
	if !db.RuleTargetSupportsCore(rule, outbounds, db.CoreXray) || !db.RuleTargetSupportsCore(rule, outbounds, db.CoreSingbox) {
		t.Fatalf("shared socks target should support both cores")
	}

	fallbackRule := db.RoutingRule{OutboundTag: "old-tag"}
	fallback, ok := db.ResolveRuleOutbound(fallbackRule, outbounds)
	if ok || fallback.ID != 0 {
		t.Fatalf("expected tag-only rule not to resolve, got outbound=%+v ok=%v", fallback, ok)
	}
	if db.RuleTargetSupportsCore(fallbackRule, outbounds, db.CoreXray) || db.RuleTargetSupportsCore(fallbackRule, outbounds, db.CoreSingbox) {
		t.Fatalf("tag-only rule should not support either core")
	}
}

func TestRoutingRuleAppliesToCoreSkipsUnknownInboundTag(t *testing.T) {
	inbounds := []db.Inbound{{ID: 1, Remark: "edge", Protocol: "vless", Core: db.CoreXray, Enabled: true}}
	rule := db.RoutingRule{InboundTag: "deleted-inbound", OutboundTag: "hy2-out", Enabled: true}
	if db.RoutingRuleAppliesToCore(rule, inbounds, db.CoreXray) || db.RoutingRuleAppliesToCore(rule, inbounds, db.CoreSingbox) {
		t.Fatal("unknown inbound_tag should not apply to any core")
	}
	valid := db.RoutingRule{InboundTag: db.GeneratedInboundTag(inbounds[0]), OutboundID: 1, OutboundTag: "direct", Enabled: true}
	if !db.RoutingRuleAppliesToCore(valid, inbounds, db.CoreXray) || db.RoutingRuleAppliesToCore(valid, inbounds, db.CoreSingbox) {
		t.Fatal("known xray inbound_tag should apply only to xray")
	}
}

func TestRoutingRuleAppliesToCorePrefersInboundIDOverTag(t *testing.T) {
	inbounds := []db.Inbound{
		{ID: 1, Remark: "edge-xray", Protocol: "vless", Core: db.CoreXray, Enabled: true},
		{ID: 2, Remark: "edge-sb", Protocol: "hysteria2", Core: db.CoreSingbox, Enabled: true},
		{ID: 3, Remark: "disabled-xray", Protocol: "vless", Core: db.CoreXray, Enabled: false},
	}
	rule := db.RoutingRule{InboundID: 2, InboundTag: db.GeneratedInboundTag(inbounds[0]), OutboundID: 1, OutboundTag: "direct", Enabled: true}
	if db.RoutingRuleAppliesToCore(rule, inbounds, db.CoreXray) {
		t.Fatal("conflicting inbound_tag must not override inbound_id")
	}
	if !db.RoutingRuleAppliesToCore(rule, inbounds, db.CoreSingbox) {
		t.Fatal("inbound_id should make the rule apply to the sing-box inbound")
	}
	missing := db.RoutingRule{InboundID: 99, InboundTag: db.GeneratedInboundTag(inbounds[0]), OutboundID: 1, OutboundTag: "direct", Enabled: true}
	if db.RoutingRuleAppliesToCore(missing, inbounds, db.CoreXray) || db.RoutingRuleAppliesToCore(missing, inbounds, db.CoreSingbox) {
		t.Fatal("missing inbound_id should not fall back to inbound_tag")
	}
	disabled := db.RoutingRule{InboundID: 3, OutboundID: 1, OutboundTag: "direct", Enabled: true}
	if db.RoutingRuleAppliesToCore(disabled, inbounds, db.CoreXray) {
		t.Fatal("disabled inbound_id should not apply to core")
	}
}

func TestStoreUpdateOutboundKeepsRoutingRuleTagSnapshot(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ob, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{
		Tag: "proxy-old", Protocol: "http", Address: "10.0.0.1", Port: 8080,
	})
	if err != nil {
		t.Fatalf("create outbound: %v", err)
	}
	rule, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{
		OutboundID:  ob.ID,
		OutboundTag: "proxy-old",
		Domain:      "geosite:netflix",
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("create routing rule: %v", err)
	}

	if _, err := store.UpdateOutbound(context.Background(), ob.ID, db.UpdateOutboundParams{
		Tag: "proxy-new", Protocol: "http", Address: "10.0.0.2", Port: 8081, Enabled: true,
	}); err != nil {
		t.Fatalf("update outbound: %v", err)
	}
	rules, err := store.ListRoutingRules(context.Background())
	if err != nil {
		t.Fatalf("list routing rules: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != rule.ID || rules[0].OutboundID != ob.ID || rules[0].OutboundTag != "proxy-old" {
		t.Fatalf("routing rule should keep outbound_id target and original tag snapshot: %+v", rules)
	}
}

func TestStoreUpdateOutboundKeepsIDTargetForIDBasedRoutingRule(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ob, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{
		Tag: "proxy-before", Protocol: "http", Address: "10.0.0.1", Port: 8080,
	})
	if err != nil {
		t.Fatalf("create outbound: %v", err)
	}
	rule, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{
		OutboundID: ob.ID,
		Domain:     "geosite:netflix",
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("create routing rule: %v", err)
	}
	if rule.OutboundID != ob.ID || rule.OutboundTag != "proxy-before" {
		t.Fatalf("expected id-based rule to store id target and tag snapshot: %+v", rule)
	}

	if _, err := store.UpdateOutbound(context.Background(), ob.ID, db.UpdateOutboundParams{
		Tag: "proxy-after", Protocol: "http", Address: "10.0.0.2", Port: 8081, Enabled: true,
	}); err != nil {
		t.Fatalf("update outbound: %v", err)
	}
	rules, err := store.ListRoutingRules(context.Background())
	if err != nil {
		t.Fatalf("list routing rules: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != rule.ID || rules[0].OutboundID != ob.ID || rules[0].OutboundTag != "proxy-before" {
		t.Fatalf("id-based routing rule should keep stable id target and original tag snapshot: %+v", rules)
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

func TestStoreDeleteOutboundRejectsReferencedOutbound(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	outbound, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{Tag: "referenced-proxy", Protocol: "socks", Address: "10.0.0.1", Port: 1080})
	if err != nil {
		t.Fatalf("create outbound: %v", err)
	}
	if _, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{OutboundID: outbound.ID, Domain: "example.com", Enabled: true}); err != nil {
		t.Fatalf("create routing rule: %v", err)
	}

	if err := store.DeleteOutbound(context.Background(), outbound.ID); err == nil || !strings.Contains(err.Error(), "referenced") {
		t.Fatalf("expected referenced outbound delete to be rejected, got %v", err)
	}
}

func TestStoreRejectsBadRoutingRuleForeignKeys(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	if err := store.ExecForTest(ctx, `INSERT INTO routing_rules (outbound_id, outbound_tag, domain, enabled, sort) VALUES (0, 'tag-only', 'example.com', 1, 0)`); err == nil {
		t.Fatal("expected outbound_id=0 routing rule to fail")
	}
	if err := store.ExecForTest(ctx, `INSERT INTO routing_rules (outbound_id, outbound_tag, domain, enabled, sort) VALUES (99999, 'missing', 'example.com', 1, 0)`); err == nil {
		t.Fatal("expected missing outbound foreign key to fail")
	}
	if err := store.ExecForTest(ctx, `INSERT INTO routing_rules (client_id, outbound_id, outbound_tag, domain, enabled, sort) VALUES (99999, 1, 'direct', 'example.com', 1, 0)`); err == nil {
		t.Fatal("expected missing client foreign key to fail")
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
	// After seeding: direct=1, blocked=2, dns=3
	o1, _ := store.CreateOutbound(context.Background(), db.CreateOutboundParams{Tag: "p1", Protocol: "socks", Address: "10.0.0.1", Port: 1080})
	o2, _ := store.CreateOutbound(context.Background(), db.CreateOutboundParams{Tag: "p2", Protocol: "http", Address: "10.0.0.2", Port: 3128})
	// Current order: direct(1), blocked(2), dns(3), p1(4), p2(5)
	// Swap: p2, p1
	err = store.ReorderOutbounds(context.Background(), []int64{o2.ID, o1.ID})
	if err != nil {
		t.Fatalf("reorder outbounds: %v", err)
	}
	list, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list after reorder: %v", err)
	}
	if len(list) != 5 {
		t.Fatalf("expected 5 outbounds, got %d", len(list))
	}
	// Defaults stay first (sort 0-2), then reordered custom outbounds (sort 3-4)
	if list[0].ID != 1 || list[1].ID != 2 || list[2].ID != 3 || list[3].ID != o2.ID || list[4].ID != o1.ID {
		t.Fatalf("expected defaults then reordered custom: got %+v", list)
	}
	if list[0].Sort != 0 || list[1].Sort != 1 || list[2].Sort != 2 || list[3].Sort != 3 || list[4].Sort != 4 {
		t.Fatalf("expected sequential sort values: got %+v", list)
	}
}

func TestStoreReorderOutboundsRejectsNonEditableIDs(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	o1, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{Tag: "p1", Protocol: "socks", Address: "10.0.0.1", Port: 1080})
	if err != nil {
		t.Fatalf("create outbound 1: %v", err)
	}
	o2, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{Tag: "p2", Protocol: "http", Address: "10.0.0.2", Port: 3128})
	if err != nil {
		t.Fatalf("create outbound 2: %v", err)
	}
	sub, err := store.CreateOutboundSubscription(context.Background(), db.CreateOutboundSubscriptionParams{
		Remark: "sub", URL: "https://example.com/sub", TagPrefix: "sub1-", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	materialized, err := store.MaterializeSubscriptionOutbounds(context.Background(), sub.ID, []db.MaterializedSubscriptionOutbound{
		{Tag: "sub1-a", Remark: "a", Protocol: "trojan", Address: "example.com", Port: 443, Password: "pw", SubscriptionIdentity: "a", Position: 0},
	}, []string{"a"})
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	var subscriptionOutboundID int64
	for _, outbound := range materialized {
		if outbound.SubscriptionIdentity == "a" {
			subscriptionOutboundID = outbound.ID
		}
	}
	if subscriptionOutboundID == 0 {
		t.Fatalf("expected materialized subscription outbound, got %+v", materialized)
	}

	cases := [][]int64{
		{subscriptionOutboundID, o1.ID},
		{1, o1.ID},
		{o1.ID, o1.ID},
		{o1.ID, 999999},
	}
	for _, ids := range cases {
		if err := store.ReorderOutbounds(context.Background(), ids); err == nil {
			t.Fatalf("expected reorder to reject ids %+v", ids)
		}
	}
	if err := store.ReorderOutbounds(context.Background(), []int64{o2.ID, o1.ID}); err != nil {
		t.Fatalf("expected valid editable reorder to succeed: %v", err)
	}
}

func TestStoreReorderOutboundsIncludesMigratedNullSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	_, err = legacy.ExecContext(context.Background(), `
CREATE TABLE outbounds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tag TEXT NOT NULL UNIQUE,
  remark TEXT NOT NULL,
  protocol TEXT NOT NULL,
  address TEXT NOT NULL DEFAULT '',
  port INTEGER NOT NULL DEFAULT 0,
  username TEXT NOT NULL DEFAULT '',
  password TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  sort INTEGER NOT NULL DEFAULT 0,
  source TEXT,
  subscription_id INTEGER NULL,
  subscription_identity TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
INSERT INTO outbounds (tag, remark, protocol, address, port, enabled, sort, source, created_at) VALUES
  ('direct', '直接连接', 'freedom', '', 0, 1, 0, 'manual', '2026-01-01T00:00:00Z'),
  ('blocked', '阻断', 'blackhole', '', 0, 1, 1, 'manual', '2026-01-01T00:00:00Z'),
  ('dns', 'DNS', 'dns', '', 0, 1, 2, 'manual', '2026-01-01T00:00:00Z'),
  ('legacy-1', 'legacy-1', 'socks', '10.0.0.1', 1080, 1, 3, NULL, '2026-01-01T00:00:00Z'),
  ('legacy-2', 'legacy-2', 'http', '10.0.0.2', 3128, 1, 4, NULL, '2026-01-01T00:00:00Z');
`)
	if err != nil {
		legacy.Close()
		t.Fatalf("seed legacy db: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}

	store, err := db.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open migrated store: %v", err)
	}
	defer store.Close()
	list, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list migrated outbounds: %v", err)
	}
	var firstID, secondID int64
	for _, outbound := range list {
		switch outbound.Tag {
		case "legacy-1":
			firstID = outbound.ID
		case "legacy-2":
			secondID = outbound.ID
		}
	}
	if firstID == 0 || secondID == 0 {
		t.Fatalf("expected legacy outbounds, got %+v", list)
	}

	if err := store.ReorderOutbounds(context.Background(), []int64{secondID, firstID}); err != nil {
		t.Fatalf("reorder migrated null-source outbounds: %v", err)
	}
	list, err = store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list after reorder: %v", err)
	}
	if list[3].ID != secondID || list[4].ID != firstID {
		t.Fatalf("expected migrated null-source outbounds to reorder, got %+v", list)
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
		InboundTag: "",
		OutboundID: 2, OutboundTag: "blocked",
		Domain:   "geosite:malware",
		IP:       "geoip:private",
		RuleSet:  "geosite-category-ads-all",
		Protocol: "bittorrent",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("create routing rule: %v", err)
	}
	if rule.OutboundTag != "blocked" || rule.Domain != "geosite:malware" || rule.IP != "geoip:private" || rule.RuleSet != "geosite-category-ads-all" || rule.Protocol != "bittorrent" || !rule.Enabled {
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
		InboundTag: "",
		OutboundID: 2, OutboundTag: "blocked",
		Domain:  "geosite:malware",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "socks-in", Protocol: "socks", Port: 2080, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	updated, err := store.UpdateRoutingRule(context.Background(), rule.ID, db.UpdateRoutingRuleParams{
		InboundTag: "socks-in",
		OutboundID: 1, OutboundTag: "direct",
		Domain:   "geosite:netflix",
		IP:       "8.8.8.8",
		RuleSet:  "geoip-cn",
		Protocol: "dns",
		Enabled:  false,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.InboundTag != inbound.Remark || updated.OutboundTag != "direct" || updated.Domain != "geosite:netflix" || updated.IP != "8.8.8.8" || updated.RuleSet != "geoip-cn" || updated.Protocol != "dns" || updated.Enabled {
		t.Fatalf("unexpected updated rule: %+v", updated)
	}

	rules, err := store.ListRoutingRules(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rules) != 1 || rules[0].Domain != "geosite:netflix" || rules[0].IP != "8.8.8.8" || rules[0].RuleSet != "geoip-cn" || rules[0].Protocol != "dns" {
		t.Fatalf("update not persisted: %+v", rules)
	}
}

func TestStoreRoutingRuleClientFields(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "edge", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "alice@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	rule, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{
		InboundTag: "edge",
		ClientID:   client.ID,
		OutboundID: 2, OutboundTag: "blocked",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("create client routing rule: %v", err)
	}
	wantInboundTag := fmt.Sprintf("inbound-%d-vless", inbound.ID)
	if rule.ClientID != client.ID || rule.ClientEmail != "alice@example.com" || rule.InboundTag != wantInboundTag {
		t.Fatalf("unexpected client routing rule: %+v", rule)
	}

	updated, err := store.UpdateRoutingRule(context.Background(), rule.ID, db.UpdateRoutingRuleParams{
		ClientID:   client.ID,
		OutboundID: 1, OutboundTag: "direct",
		Domain:  "example.com",
		Enabled: false,
	})
	if err != nil {
		t.Fatalf("update client routing rule: %v", err)
	}
	if updated.ClientID != client.ID || updated.ClientEmail != "alice@example.com" || updated.OutboundTag != "direct" || updated.Enabled {
		t.Fatalf("unexpected updated client routing rule: %+v", updated)
	}

	rules, err := store.ListRoutingRules(context.Background())
	if err != nil {
		t.Fatalf("list routing rules: %v", err)
	}
	if len(rules) != 1 || rules[0].ClientID != client.ID || rules[0].ClientEmail != "alice@example.com" {
		t.Fatalf("client fields not persisted: %+v", rules)
	}
}

func TestStoreRejectsRoutingRuleWithUnsupportedOutboundCore(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	xrayInbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "xray-in", Protocol: "vless", Port: 23001, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create xray inbound: %v", err)
	}
	singboxInbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "sb-in", Protocol: "hysteria2", Port: 23002, Network: "udp", Security: "tls"})
	if err != nil {
		t.Fatalf("create sing-box inbound: %v", err)
	}
	singboxOnly, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{Tag: "hy2-out", Protocol: "hysteria2", Address: "127.0.0.1", Port: 443, Password: "secret"})
	if err != nil {
		t.Fatalf("create sing-box outbound: %v", err)
	}
	shared, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{Tag: "shared-socks", Protocol: "socks", Address: "127.0.0.1", Port: 1080})
	if err != nil {
		t.Fatalf("create shared outbound: %v", err)
	}

	if _, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{InboundTag: db.GeneratedInboundTag(xrayInbound), OutboundID: singboxOnly.ID, Enabled: true}); err == nil {
		t.Fatal("expected xray inbound to reject sing-box-only outbound")
	}
	if !db.SupportsCore(shared.SupportedCores, db.CoreSingbox) {
		t.Fatalf("shared protocol should be derived as sing-box capable: %+v", shared.SupportedCores)
	}
	if _, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{InboundTag: db.GeneratedInboundTag(singboxInbound), OutboundID: shared.ID, Enabled: true}); err != nil {
		t.Fatalf("expected sing-box inbound to accept shared outbound: %v", err)
	}
	if _, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{InboundTag: db.GeneratedInboundTag(singboxInbound), OutboundID: singboxOnly.ID, Enabled: true}); err != nil {
		t.Fatalf("expected sing-box inbound to accept sing-box outbound: %v", err)
	}
}

func TestStoreRejectsRoutingRuleClientInboundMismatch(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "edge", Protocol: "vless", Port: 443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "alice@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	_, err = store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{
		InboundTag: "other-inbound",
		ClientID:   client.ID,
		OutboundID: 1, OutboundTag: "direct",
		Enabled: true,
	})
	if err == nil {
		t.Fatal("expected client inbound mismatch to be rejected")
	}
}

func TestStoreRejectsRoutingRuleClientEmailWithoutClientID(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	_, err = store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{
		InboundTag:  "inbound-1-vless",
		ClientEmail: "alice@example.com",
		OutboundID:  1, OutboundTag: "direct",
		Enabled: true,
	})
	if err == nil {
		t.Fatal("expected client_email without client_id to be rejected")
	}
}

func TestStoreDeleteRoutingRule(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	rule, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{
		OutboundID: 2, OutboundTag: "blocked", Domain: "geosite:malware",
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

func TestStoreMigratesLegacyOutboundsBeforeCreatingSubscriptionIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-index.db")
	legacy, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	_, err = legacy.ExecContext(context.Background(), `
CREATE TABLE outbounds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tag TEXT NOT NULL UNIQUE,
  remark TEXT NOT NULL,
  protocol TEXT NOT NULL,
  address TEXT NOT NULL DEFAULT '',
  port INTEGER NOT NULL DEFAULT 0,
  username TEXT NOT NULL DEFAULT '',
  password TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  sort INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
INSERT INTO outbounds (tag, remark, protocol, address, port, enabled, sort, created_at) VALUES
  ('legacy-1', 'legacy-1', 'socks', '10.0.0.1', 1080, 1, 0, '2026-01-01T00:00:00Z');
`)
	if err != nil {
		legacy.Close()
		t.Fatalf("seed legacy db: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}

	store, err := db.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open migrated store: %v", err)
	}
	defer store.Close()

	outbounds, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list migrated outbounds: %v", err)
	}
	var found bool
	for _, outbound := range outbounds {
		if outbound.Tag == "legacy-1" {
			found = true
			if outbound.Source != "manual" {
				t.Fatalf("expected migrated source manual, got %+v", outbound)
			}
		}
	}
	if !found {
		t.Fatalf("expected legacy outbound after migration, got %+v", outbounds)
	}

	check, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open migrated db for index check: %v", err)
	}
	defer check.Close()
	var indexName string
	if err := check.QueryRowContext(context.Background(), `SELECT name FROM sqlite_master WHERE type='index' AND name='idx_outbounds_subscription'`).Scan(&indexName); err != nil {
		t.Fatalf("expected subscription index after migration: %v", err)
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
	disabled := false
	disabledClient, err := store.CreateClient(context.Background(), db.CreateClientParams{
		InboundID: inbound.ID,
		Email:     "disabled@example.com",
		Enabled:   &disabled,
	})
	if err != nil {
		t.Fatalf("create disabled client: %v", err)
	}
	if disabledClient.Enabled != false {
		t.Fatalf("expected disabled client, got %+v", disabledClient)
	}

	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(inbounds) != 1 || len(inbounds[0].Clients) != 2 {
		t.Fatalf("expected inbound with two clients, got %+v", inbounds)
	}
	if inbounds[0].Clients[0].Email != "sam@example.com" {
		t.Fatalf("unexpected client email: %+v", inbounds[0].Clients[0])
	}
	if inbounds[0].Clients[1].Email != "disabled@example.com" || inbounds[0].Clients[1].Enabled {
		t.Fatalf("disabled client not persisted: %+v", inbounds[0].Clients[1])
	}
}

func TestStoreRejectsDuplicateClientEmailAndUUID(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "dupe", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	_, err = store.CreateClient(context.Background(), db.CreateClientParams{
		InboundID: inbound.ID, Email: "sam@example.com", UUID: "11111111-1111-4111-8111-111111111111",
	})
	if err != nil {
		t.Fatalf("create first client: %v", err)
	}
	if _, err := store.CreateClient(context.Background(), db.CreateClientParams{
		InboundID: inbound.ID, Email: "sam@example.com", UUID: "22222222-2222-4222-8222-222222222222",
	}); err == nil || !strings.Contains(err.Error(), "duplicate client email") {
		t.Fatalf("expected duplicate client email error, got %v", err)
	}
	if _, err := store.CreateClient(context.Background(), db.CreateClientParams{
		InboundID: inbound.ID, Email: "other@example.com", UUID: "11111111-1111-4111-8111-111111111111",
	}); err == nil || !strings.Contains(err.Error(), "duplicate client uuid") {
		t.Fatalf("expected duplicate client uuid error, got %v", err)
	}
	second, err := store.CreateClient(context.Background(), db.CreateClientParams{
		InboundID: inbound.ID, Email: "other@example.com", UUID: "33333333-3333-4333-8333-333333333333",
	})
	if err != nil {
		t.Fatalf("create second client: %v", err)
	}
	if _, err := store.UpdateClient(context.Background(), second.ID, db.UpdateClientParams{
		Email: "sam@example.com", Enabled: true,
	}); err == nil || !strings.Contains(err.Error(), "duplicate client email") {
		t.Fatalf("expected duplicate client email on update, got %v", err)
	}
	if _, err := store.UpdateClient(context.Background(), second.ID, db.UpdateClientParams{
		Email: "other@example.com", UUID: "11111111-1111-4111-8111-111111111111", Enabled: true,
	}); err == nil || !strings.Contains(err.Error(), "duplicate client uuid") {
		t.Fatalf("expected duplicate client uuid on update, got %v", err)
	}
}

func TestStoreRejectsUnsupportedProtocol(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	for _, protocol := range []string{"wireguard"} {
		_, err = store.CreateInbound(context.Background(), db.CreateInboundParams{
			Protocol: protocol,
			Port:     8080,
		})
		if err == nil {
			t.Fatalf("expected error for unsupported protocol %q", protocol)
		}
	}
}

func TestStoreAutoAssignsInboundPort(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	first, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "auto-a", Protocol: "vless", Port: 0, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create first auto-port inbound: %v", err)
	}
	if first.Port < 20000 || first.Port > 60000 {
		t.Fatalf("expected auto-assigned port in range 20000-60000, got %+v", first)
	}

	second, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "auto-b", Protocol: "vmess", Port: 0, Network: "ws", Security: "tls",
	})
	if err != nil {
		t.Fatalf("create second auto-port inbound: %v", err)
	}
	if second.Port == first.Port {
		t.Fatalf("auto-assigned duplicate port: first=%+v second=%+v", first, second)
	}
	if second.Port < 20000 || second.Port > 60000 {
		t.Fatalf("expected second auto-assigned port in range 20000-60000, got %+v", second)
	}

	seen := map[int]bool{first.Port: true, second.Port: true}
	for i := 0; i < 8; i++ {
		inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
			Remark: fmt.Sprintf("auto-extra-%d", i), Protocol: "trojan", Port: 0, Network: "tcp", Security: "tls",
		})
		if err != nil {
			t.Fatalf("create extra auto-port inbound %d: %v", i, err)
		}
		if inbound.Port < 20000 || inbound.Port > 60000 {
			t.Fatalf("expected extra auto-assigned port in range 20000-60000, got %+v", inbound)
		}
		if seen[inbound.Port] {
			t.Fatalf("auto-assigned duplicate port %d after ports %+v", inbound.Port, seen)
		}
		seen[inbound.Port] = true
	}
}

func TestStoreRejectsDuplicateInboundPort(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "first", Protocol: "vless", Port: 18450, Network: "tcp", Security: "none",
	}); err != nil {
		t.Fatalf("create first inbound: %v", err)
	}
	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "second", Protocol: "vmess", Port: 18450, Network: "ws", Security: "tls",
	}); err == nil {
		t.Fatal("expected duplicate inbound port to be rejected")
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

func TestStoreDeleteClientCleansRoutingRules(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "client-route", Protocol: "vless", Port: 443, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "route-client@test.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if _, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{ClientID: client.ID, OutboundID: 1, OutboundTag: "direct", Enabled: true}); err != nil {
		t.Fatalf("create client routing rule: %v", err)
	}

	if err := store.DeleteClient(context.Background(), client.ID); err != nil {
		t.Fatalf("delete client: %v", err)
	}
	rules, err := store.ListRoutingRules(context.Background())
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected client routing rules to be removed, got %+v", rules)
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

func TestStoreEnablesForeignKeysForConnections(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	err = store.ExecForTest(context.Background(), `
INSERT INTO clients (inbound_id, uuid, credential_id, password, subscription_token, stats_key, email, enabled, created_at)
VALUES (99999, 'orphan-uuid', 'orphan-uuid', '', 'orphan-token', 'orphan-stats', 'orphan@example.com', 1, 'now')
`)
	if err == nil {
		t.Fatal("expected foreign key violation for missing inbound")
	}
}

func TestStoreDeleteInboundCleansRoutingRulesAndClients(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "route-inbound", Protocol: "vless", Port: 9443, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "inbound-client@test.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if _, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{InboundTag: db.GeneratedInboundTag(inbound), OutboundID: 1, OutboundTag: "direct", Enabled: true}); err != nil {
		t.Fatalf("create inbound routing rule: %v", err)
	}
	if _, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{ClientID: client.ID, OutboundID: 2, OutboundTag: "blocked", Enabled: true}); err != nil {
		t.Fatalf("create client routing rule: %v", err)
	}

	if err := store.DeleteInbound(context.Background(), inbound.ID); err != nil {
		t.Fatalf("delete inbound: %v", err)
	}
	rules, err := store.ListRoutingRules(context.Background())
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected inbound and client routing rules to be removed, got %+v", rules)
	}
	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	for _, item := range inbounds {
		for _, listedClient := range item.Clients {
			if listedClient.ID == client.ID {
				t.Fatalf("expected inbound client to be removed, got %+v", listedClient)
			}
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

func TestStoreUpdateInboundCascadesRoutingRuleInboundTag(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "old-edge", Protocol: "vless", Port: 443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	remarkRule, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{
		InboundTag: "old-edge",
		OutboundID: 2, OutboundTag: "blocked",
		Domain:  "geosite:netflix",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("create remark routing rule: %v", err)
	}
	generatedRule, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{
		InboundTag: fmt.Sprintf("inbound-%d-vless", inbound.ID),
		OutboundID: 1, OutboundTag: "direct",
		Domain:  "example.com",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("create generated routing rule: %v", err)
	}

	if _, err := store.UpdateInbound(context.Background(), inbound.ID, db.UpdateInboundParams{
		Remark: "new-edge", Protocol: "vmess", Port: 8443, Network: "ws", Security: "tls", Enabled: true,
	}); err != nil {
		t.Fatalf("update inbound: %v", err)
	}
	rules, err := store.ListRoutingRules(context.Background())
	if err != nil {
		t.Fatalf("list routing rules: %v", err)
	}
	got := map[int64]db.RoutingRule{}
	for _, rule := range rules {
		got[rule.ID] = rule
	}
	if got[remarkRule.ID].InboundTag != "new-edge" {
		t.Fatalf("remark inbound tag was not cascaded: %+v", rules)
	}
	if got[generatedRule.ID].InboundTag != fmt.Sprintf("inbound-%d-vmess", inbound.ID) {
		t.Fatalf("generated inbound tag was not cascaded: %+v", rules)
	}
	if got[remarkRule.ID].InboundID != inbound.ID || got[generatedRule.ID].InboundID != inbound.ID {
		t.Fatalf("inbound_id should remain bound to updated inbound: %+v", rules)
	}
}

func TestStoreRoutingRuleInboundIDSurvivesInboundRename(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "old-edge", Protocol: "vless", Port: 1443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	rule, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{
		InboundID: inbound.ID, OutboundID: 1, OutboundTag: "direct", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create routing rule: %v", err)
	}
	if rule.InboundID != inbound.ID || rule.InboundTag != db.GeneratedInboundTag(inbound) {
		t.Fatalf("expected rule to store inbound_id target and tag snapshot: %+v", rule)
	}
	if _, err := store.UpdateInbound(context.Background(), inbound.ID, db.UpdateInboundParams{
		Remark: "new-edge", Protocol: "vmess", Port: 2443, Network: "ws", Security: "tls", Enabled: true,
	}); err != nil {
		t.Fatalf("update inbound: %v", err)
	}
	rules, err := store.ListRoutingRules(context.Background())
	if err != nil {
		t.Fatalf("list routing rules: %v", err)
	}
	if len(rules) != 1 || rules[0].InboundID != inbound.ID || rules[0].InboundTag != fmt.Sprintf("inbound-%d-vmess", inbound.ID) {
		t.Fatalf("rule should remain bound to inbound_id after rename/protocol change: %+v", rules)
	}
}

func TestStoreUpdateInboundDoesNotCascadeDuplicateRemarkRules(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	first, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "shared-edge", Protocol: "vless", Port: 443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create first inbound: %v", err)
	}
	second, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "shared-edge", Protocol: "vmess", Port: 8443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create second inbound: %v", err)
	}
	remarkRule, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{
		InboundTag: "shared-edge",
		OutboundID: 2, OutboundTag: "blocked",
		Domain:  "geosite:netflix",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("create remark routing rule: %v", err)
	}
	generatedRule, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{
		InboundTag: fmt.Sprintf("inbound-%d-vless", first.ID),
		OutboundID: 1, OutboundTag: "direct",
		Domain:  "example.com",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("create generated routing rule: %v", err)
	}

	if _, err := store.UpdateInbound(context.Background(), first.ID, db.UpdateInboundParams{
		Remark: "renamed-edge", Protocol: "trojan", Port: 9443, Network: "tcp", Security: "tls", Enabled: true,
	}); err != nil {
		t.Fatalf("update inbound: %v", err)
	}
	rules, err := store.ListRoutingRules(context.Background())
	if err != nil {
		t.Fatalf("list routing rules: %v", err)
	}
	got := map[int64]string{}
	for _, rule := range rules {
		got[rule.ID] = rule.InboundTag
	}
	if got[remarkRule.ID] != "shared-edge" {
		t.Fatalf("duplicate remark rule should not be cascaded: %+v", rules)
	}
	if got[generatedRule.ID] != fmt.Sprintf("inbound-%d-trojan", first.ID) {
		t.Fatalf("generated inbound tag should still be cascaded: %+v", rules)
	}
	if second.ID == first.ID {
		t.Fatal("test setup produced duplicate inbound IDs")
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

func TestStoreUpdateInboundRejectsUnsupportedProtocol(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "test", Protocol: "vless", Port: 8443, Network: "tcp",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	for _, protocol := range []string{join("vpn", "gate", "_soft", "ether"), "wireguard"} {
		_, err = store.UpdateInbound(context.Background(), inbound.ID, db.UpdateInboundParams{
			Remark: "test", Protocol: protocol, Port: 8443, Network: "tcp", Enabled: true,
		})
		if err == nil {
			t.Fatalf("expected unsupported protocol error for %q", protocol)
		}
	}
}

func TestStoreUpdateInboundRejectsProtocolChangeWithIncompatibleClients(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "edge", Protocol: "vless", Port: 18443, Network: "tcp", Security: "none",
		InitialClient: &db.CreateClientParams{
			Email: "uuid-only",
			UUID:  "11111111-1111-4111-8111-111111111111",
		},
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	_, err = store.UpdateInbound(context.Background(), inbound.ID, db.UpdateInboundParams{
		Remark: "edge", Protocol: "tuic", Port: 18443, Network: "udp", Security: "tls", Enabled: true,
	})
	if err == nil || !strings.Contains(err.Error(), "tuic") || !strings.Contains(err.Error(), "uuid-only") {
		t.Fatalf("expected target protocol and client label in error, got %v", err)
	}

	for _, protocol := range []string{"socks", "http"} {
		_, err = store.UpdateInbound(context.Background(), inbound.ID, db.UpdateInboundParams{
			Remark: "edge", Protocol: protocol, Port: 18443, Network: "tcp", Security: "none", Enabled: true,
		})
		if err == nil || !strings.Contains(err.Error(), protocol) || !strings.Contains(err.Error(), "uuid-only") {
			t.Fatalf("expected %s credential incompatibility, got %v", protocol, err)
		}
	}

	loaded, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Protocol != "vless" {
		t.Fatalf("protocol update should have been rejected without mutation: %+v", loaded)
	}
}

func TestStoreUpdateInboundAllowsPasswordProtocolChangeWhenCredentialsMatch(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "password-edge", Protocol: "trojan", Port: 18444, Network: "tcp", Security: "tls",
		InitialClient: &db.CreateClientParams{
			Email:    "password-client",
			UUID:     "secret-password",
			Password: "secret-password",
		},
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	updated, err := store.UpdateInbound(context.Background(), inbound.ID, db.UpdateInboundParams{
		Remark: "password-edge", Protocol: "hysteria2", Port: 18444, Network: "udp", Security: "tls", Enabled: true,
	})
	if err != nil {
		t.Fatalf("password protocol change should be allowed: %v", err)
	}
	if updated.Protocol != "hysteria2" {
		t.Fatalf("unexpected protocol: %+v", updated)
	}
}

func TestStoreUpdateInboundAllowsProtocolChangeWithoutClients(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "empty-edge", Protocol: "vless", Port: 18445, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	updated, err := store.UpdateInbound(context.Background(), inbound.ID, db.UpdateInboundParams{
		Remark: "empty-edge", Protocol: "http", Port: 18445, Network: "tcp", Security: "none", Enabled: true,
	})
	if err != nil {
		t.Fatalf("protocol change without clients should be allowed: %v", err)
	}
	if updated.Protocol != "http" {
		t.Fatalf("unexpected protocol: %+v", updated)
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

	updated, err = store.UpdateClient(context.Background(), client.ID, db.UpdateClientParams{
		Email:   "new@test.com",
		UUID:    "22222222-2222-4222-8222-222222222222",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("update client uuid: %v", err)
	}
	if updated.UUID != "22222222-2222-4222-8222-222222222222" || !updated.Enabled {
		t.Fatalf("uuid/enabled not updated: %+v", updated)
	}

	loaded, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(loaded) != 1 || len(loaded[0].Clients) != 1 || loaded[0].Clients[0].Email != "new@test.com" || loaded[0].Clients[0].UUID != "22222222-2222-4222-8222-222222222222" || loaded[0].Clients[0].Enabled != true {
		t.Fatalf("updated client not persisted: %+v", loaded[0].Clients[0])
	}
}

func TestStoreUpdateClientCascadesRoutingRuleClientEmail(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "edge", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "old@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	rule, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{
		InboundTag: "edge",
		ClientID:   client.ID,
		OutboundID: 2, OutboundTag: "blocked",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("create client routing rule: %v", err)
	}

	if _, err := store.UpdateClient(context.Background(), client.ID, db.UpdateClientParams{
		Email: "new@example.com", UUID: client.UUID, Enabled: true,
	}); err != nil {
		t.Fatalf("update client: %v", err)
	}
	rules, err := store.ListRoutingRules(context.Background())
	if err != nil {
		t.Fatalf("list routing rules: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != rule.ID || rules[0].ClientEmail != "new@example.com" {
		t.Fatalf("client email was not cascaded to routing rule: %+v", rules)
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

func TestStoreCreateInboundInitialClientIgnoresInputInboundID(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	existing, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "existing", Protocol: "vless", Port: 18452, Network: "tcp", Security: "none",
		InitialClient: &db.CreateClientParams{
			Email: "same-email@test.com",
			UUID:  "11111111-1111-4111-8111-111111111111",
		},
	})
	if err != nil {
		t.Fatalf("create existing inbound: %v", err)
	}

	created, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "new", Protocol: "vless", Port: 18453, Network: "tcp", Security: "none",
		InitialClient: &db.CreateClientParams{
			InboundID: existing.ID,
			Email:     "same-email@test.com",
			UUID:      "22222222-2222-4222-8222-222222222222",
		},
	})
	if err != nil {
		t.Fatalf("create inbound should ignore initial client inbound_id: %v", err)
	}
	if len(created.Clients) != 1 || created.Clients[0].InboundID != created.ID {
		t.Fatalf("initial client was not attached to the new inbound: %+v", created)
	}
}

func TestStoreCreateInboundWithInvalidInitialClientIsAtomic(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	_, err = store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark:   "bad-init-client",
		Protocol: "tuic",
		Port:     18446,
		Network:  "udp",
		Security: "tls",
		InitialClient: &db.CreateClientParams{
			Email:        "bad-tuic@test.com",
			CredentialID: "not-a-uuid",
			Password:     "tuic-secret",
		},
	})
	if err == nil {
		t.Fatal("expected invalid initial client to fail")
	}

	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(inbounds) != 0 {
		t.Fatalf("invalid initial client must not leave a half-created inbound: %+v", inbounds)
	}
}

func TestStoreCreateInboundWithDuplicateInitialClientCredentialIDIsAtomic(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	_, err = store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "first-trojan", Protocol: "trojan", Port: 18448, Network: "tcp", Security: "tls",
		InitialClient: &db.CreateClientParams{
			Email:        "first-trojan@test.com",
			CredentialID: "shared-credential-id",
			Password:     "first-secret",
		},
	})
	if err != nil {
		t.Fatalf("create first inbound: %v", err)
	}

	_, err = store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "duplicate-trojan", Protocol: "trojan", Port: 18449, Network: "tcp", Security: "tls",
		InitialClient: &db.CreateClientParams{
			Email:        "duplicate-trojan@test.com",
			CredentialID: "shared-credential-id",
			Password:     "other-secret",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate client credential_id") {
		t.Fatalf("expected duplicate credential_id error, got %v", err)
	}

	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(inbounds) != 1 || inbounds[0].Remark != "first-trojan" {
		t.Fatalf("duplicate initial client must not leave a half-created inbound: %+v", inbounds)
	}
}

func TestStoreCreateInboundWithValidTUICInitialClientPersistsBoth(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark:   "tuic-init-client",
		Protocol: "tuic",
		Port:     18447,
		Network:  "udp",
		Security: "tls",
		InitialClient: &db.CreateClientParams{
			Email:        "tuic@test.com",
			CredentialID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			Password:     "tuic-secret",
		},
	})
	if err != nil {
		t.Fatalf("create tuic inbound with initial client: %v", err)
	}
	if inbound.Protocol != "tuic" || len(inbound.Clients) != 1 {
		t.Fatalf("unexpected created inbound: %+v", inbound)
	}
	if inbound.Clients[0].CredentialID != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" || inbound.Clients[0].Password != "tuic-secret" {
		t.Fatalf("unexpected initial client credentials: %+v", inbound.Clients[0])
	}

	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(inbounds) != 1 || len(inbounds[0].Clients) != 1 {
		t.Fatalf("expected inbound and client to persist together: %+v", inbounds)
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

func TestStoreRejectsRemovedLegacyOutbound(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	_, err = store.CreateOutbound(context.Background(), db.CreateOutboundParams{
		Tag:      "removed-vpn-outbound",
		Remark:   "removed VPN feature",
		Protocol: join("vpn", "gate", "_soft", "ether"),
		Address:  "10.77.1.2",
		Port:     21080,
	})
	if err == nil {
		t.Fatal("expected removed outbound protocol to be rejected after removal")
	}
}

func TestStoreRejectsRemovedLegacyPoolVirtualOutbound(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	_, err = store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{OutboundTag: join("vpn", "gate", "-pool"), Domain: "geosite:google", Enabled: true})
	if err == nil {
		t.Fatal("expected removed virtual outbound to be rejected")
	}
}

func TestStoreCreateRoutingRuleRejectsMissingOutboundID(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	_, err = store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{
		OutboundTag: "nonexistent",
		Domain:      "example.com",
		Enabled:     true,
	})
	if err == nil {
		t.Fatal("expected error for missing outbound_id, got nil")
	}
}

func TestStoreUpdateRoutingRuleRejectsMissingOutboundID(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	rule, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{
		OutboundID: 2, OutboundTag: "blocked",
		Domain:  "geosite:malware",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}

	_, err = store.UpdateRoutingRule(context.Background(), rule.ID, db.UpdateRoutingRuleParams{
		OutboundTag: "nonexistent",
		Domain:      "geosite:netflix",
		Enabled:     false,
	})
	if err == nil {
		t.Fatal("expected error for missing outbound_id on update, got nil")
	}
}

func TestStoreReorderRoutingRulesUpdatesSortOrder(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	r1, _ := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{
		OutboundID: 2, OutboundTag: "blocked", Domain: "geosite:malware", Enabled: true,
	})
	r2, _ := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{
		OutboundID: 2, OutboundTag: "blocked", Domain: "geosite:netflix", Enabled: true,
	})

	err = store.ReorderRoutingRules(context.Background(), []int64{r2.ID, r1.ID})
	if err != nil {
		t.Fatalf("reorder routing rules: %v", err)
	}

	list, err := store.ListRoutingRules(context.Background())
	if err != nil {
		t.Fatalf("list after reorder: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 routing rules, got %d", len(list))
	}
	if list[0].ID != r2.ID || list[1].ID != r1.ID {
		t.Fatalf("expected rules in order [%d, %d], got [%d, %d]", r2.ID, r1.ID, list[0].ID, list[1].ID)
	}
}

func TestStoreListRoutingRulesUsesIDForEqualSort(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	r1, err := store.CreateRoutingRule(ctx, db.CreateRoutingRuleParams{OutboundID: 2, OutboundTag: "blocked", Domain: "geosite:malware", Enabled: true})
	if err != nil {
		t.Fatalf("create first rule: %v", err)
	}
	r2, err := store.CreateRoutingRule(ctx, db.CreateRoutingRuleParams{OutboundID: 2, OutboundTag: "blocked", Domain: "geosite:netflix", Enabled: true})
	if err != nil {
		t.Fatalf("create second rule: %v", err)
	}
	if err := store.ExecForTest(ctx, `UPDATE routing_rules SET sort=0`); err != nil {
		t.Fatalf("force equal sort: %v", err)
	}
	list, err := store.ListRoutingRules(ctx)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(list) != 2 || list[0].ID != r1.ID || list[1].ID != r2.ID {
		t.Fatalf("expected equal sort rules to be ordered by id [%d, %d], got %+v", r1.ID, r2.ID, list)
	}
}

func TestStoreBlacklistAddAndCheck(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	hash := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	expires := time.Now().Add(24 * time.Hour)

	// Add as active session (revoked=false)
	if err := store.AddToBlacklist(ctx, hash, expires, false); err != nil {
		t.Fatalf("AddToBlacklist: %v", err)
	}

	// Should not be blacklisted
	revoked, err := store.IsBlacklisted(ctx, hash)
	if err != nil {
		t.Fatalf("IsBlacklisted: %v", err)
	}
	if revoked {
		t.Fatal("expected session to NOT be blacklisted yet")
	}

	// Revoke it
	if err := store.AddToBlacklist(ctx, hash, expires, true); err != nil {
		t.Fatalf("AddToBlacklist (revoke): %v", err)
	}

	// Should now be blacklisted
	revoked, err = store.IsBlacklisted(ctx, hash)
	if err != nil {
		t.Fatalf("IsBlacklisted: %v", err)
	}
	if !revoked {
		t.Fatal("expected session to be blacklisted after revoke")
	}
}

func TestStoreBlacklistExpiredEntry(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	hash := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	// Add with already-expired timestamp
	expires := time.Now().Add(-1 * time.Hour)
	if err := store.AddToBlacklist(ctx, hash, expires, true); err != nil {
		t.Fatalf("AddToBlacklist: %v", err)
	}

	// Should be auto-cleaned and not blacklisted
	revoked, err := store.IsBlacklisted(ctx, hash)
	if err != nil {
		t.Fatalf("IsBlacklisted: %v", err)
	}
	if revoked {
		t.Fatal("expected expired entry to be auto-cleaned")
	}
}

func TestStoreListActiveSessions(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	expires := time.Now().Add(24 * time.Hour)

	hash1 := "1111111111111111111111111111111111111111111111111111111111111111"
	hash2 := "2222222222222222222222222222222222222222222222222222222222222222"
	hash3 := "3333333333333333333333333333333333333333333333333333333333333333"

	// Add two active sessions
	if err := store.AddToBlacklist(ctx, hash1, expires, false); err != nil {
		t.Fatalf("AddToBlacklist hash1: %v", err)
	}
	if err := store.AddToBlacklist(ctx, hash2, expires, false); err != nil {
		t.Fatalf("AddToBlacklist hash2: %v", err)
	}
	// Add one revoked session
	if err := store.AddToBlacklist(ctx, hash3, expires, true); err != nil {
		t.Fatalf("AddToBlacklist hash3: %v", err)
	}

	sessions, err := store.ListActiveSessions(ctx)
	if err != nil {
		t.Fatalf("ListActiveSessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 active sessions, got %d", len(sessions))
	}
}

func TestStoreRevokeSessionByID(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	expires := time.Now().Add(24 * time.Hour)

	if err := store.AddToBlacklist(ctx, hash, expires, false); err != nil {
		t.Fatalf("AddToBlacklist: %v", err)
	}

	// List to get the ID
	sessions, err := store.ListActiveSessions(ctx)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("expected 1 active session, got %d: %v", len(sessions), err)
	}

	// Revoke by ID
	if err := store.RevokeSession(ctx, sessions[0].ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}

	// Should be blacklisted now
	revoked, err := store.IsBlacklisted(ctx, hash)
	if err != nil {
		t.Fatalf("IsBlacklisted: %v", err)
	}
	if !revoked {
		t.Fatal("expected session to be revoked")
	}

	// Revoking again should fail (already revoked)
	if err := store.RevokeSession(ctx, sessions[0].ID); err == nil {
		t.Fatal("expected error when revoking already-revoked session")
	}
}

func TestStorePruneActiveSessions(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	expires := time.Now().Add(24 * time.Hour)
	for i := 0; i < 4; i++ {
		hash := fmt.Sprintf("%064d", i)
		if err := store.AddToBlacklist(ctx, hash, expires, false); err != nil {
			t.Fatalf("AddToBlacklist %d: %v", i, err)
		}
	}

	if err := store.PruneActiveSessions(ctx, 2); err != nil {
		t.Fatalf("PruneActiveSessions: %v", err)
	}
	sessions, err := store.ListActiveSessions(ctx)
	if err != nil {
		t.Fatalf("ListActiveSessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 active sessions, got %d", len(sessions))
	}
	if sessions[0].TokenHash != fmt.Sprintf("%064d", 3) || sessions[1].TokenHash != fmt.Sprintf("%064d", 2) {
		t.Fatalf("expected newest sessions to remain, got %+v", sessions)
	}
}

func TestStoreRevokeOtherSessions(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	expires := time.Now().Add(24 * time.Hour)
	current := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	other := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	revokedHash := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if err := store.AddToBlacklist(ctx, current, expires, false); err != nil {
		t.Fatalf("AddToBlacklist current: %v", err)
	}
	if err := store.AddToBlacklist(ctx, other, expires, false); err != nil {
		t.Fatalf("AddToBlacklist other: %v", err)
	}
	if err := store.AddToBlacklist(ctx, revokedHash, expires, true); err != nil {
		t.Fatalf("AddToBlacklist revoked: %v", err)
	}

	n, err := store.RevokeOtherSessions(ctx, current)
	if err != nil {
		t.Fatalf("RevokeOtherSessions: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 revoked session, got %d", n)
	}
	sessions, err := store.ListActiveSessions(ctx)
	if err != nil {
		t.Fatalf("ListActiveSessions: %v", err)
	}
	if len(sessions) != 1 || sessions[0].TokenHash != current {
		t.Fatalf("expected only current session to remain, got %+v", sessions)
	}
}

func TestStoreUpdateClientTrafficBatch(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "batch", Protocol: "vless", Port: 28080, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	clientA, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "a@example.com"})
	if err != nil {
		t.Fatalf("create client a: %v", err)
	}
	clientB, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "b@example.com"})
	if err != nil {
		t.Fatalf("create client b: %v", err)
	}

	err = store.UpdateClientTrafficBatch(ctx, map[string]db.ClientTrafficUpdate{
		clientA.StatsKey:      {Up: 11, Down: 22},
		clientB.StatsKey:      {Up: 33, Down: 44},
		"missing@example.com": {Up: 55, Down: 66},
	})
	if err != nil {
		t.Fatalf("batch update traffic: %v", err)
	}
	err = store.UpdateClientTrafficBatch(ctx, map[string]db.ClientTrafficUpdate{
		clientA.StatsKey: {Up: 21, Down: 42},
		clientB.StatsKey: {Up: 63, Down: 84},
	})
	if err != nil {
		t.Fatalf("second batch update traffic: %v", err)
	}

	inbounds, err := store.ListInbounds(ctx)
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	traffic := map[string][2]int64{}
	for _, client := range inbounds[0].Clients {
		traffic[client.Email] = [2]int64{client.Up, client.Down}
	}
	if traffic["a@example.com"] != [2]int64{10, 20} || traffic["b@example.com"] != [2]int64{30, 40} {
		t.Fatalf("unexpected traffic after batch update: %+v", traffic)
	}
}

func TestStoreGetSubscriptionByClientUUIDLoadsOnlyMatchedClient(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "sub", Protocol: "vless", Port: 443, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	target, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "target@example.com"})
	if err != nil {
		t.Fatalf("create target client: %v", err)
	}
	if _, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "other@example.com"}); err != nil {
		t.Fatalf("create other client: %v", err)
	}

	loadedInbound, loadedClient, found, err := store.GetSubscriptionByClientUUID(ctx, target.UUID)
	if err != nil {
		t.Fatalf("get subscription: %v", err)
	}
	if !found {
		t.Fatal("expected subscription client to be found")
	}
	if loadedInbound.ID != inbound.ID || loadedClient.ID != target.ID || loadedClient.Email != "target@example.com" {
		t.Fatalf("unexpected subscription row: inbound=%+v client=%+v", loadedInbound, loadedClient)
	}
	if len(loadedInbound.Clients) != 1 || loadedInbound.Clients[0].ID != target.ID {
		t.Fatalf("subscription query should attach only the matched client, got %+v", loadedInbound.Clients)
	}

	_, _, found, err = store.GetSubscriptionByClientUUID(ctx, "missing")
	if err != nil {
		t.Fatalf("get missing subscription: %v", err)
	}
	if found {
		t.Fatal("expected missing subscription to return found=false")
	}
}

func TestStoreCreatesAndLooksUpIndependentSubscriptionToken(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "sub-token", Protocol: "vless", Port: 9443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "token@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if client.SubscriptionToken == "" || client.SubscriptionToken == client.UUID {
		t.Fatalf("expected independent subscription token, got client=%+v", client)
	}

	loadedInbound, loadedClient, found, err := store.GetSubscriptionByToken(ctx, client.SubscriptionToken)
	if err != nil {
		t.Fatalf("lookup by token: %v", err)
	}
	if !found || loadedInbound.ID != inbound.ID || loadedClient.ID != client.ID {
		t.Fatalf("unexpected token lookup result: found=%v inbound=%+v client=%+v", found, loadedInbound, loadedClient)
	}
}

func TestStoreUpdateClientTrafficByStatsKeyDoesNotPolluteDuplicateEmailsAcrossInbounds(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	first, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "first", Protocol: "vless", Port: 28081, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create first inbound: %v", err)
	}
	second, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "second", Protocol: "vless", Port: 28082, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create second inbound: %v", err)
	}
	firstClient, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: first.ID, Email: "shared@example.com"})
	if err != nil {
		t.Fatalf("create first shared client: %v", err)
	}
	secondClient, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: second.ID, Email: "shared@example.com"})
	if err != nil {
		t.Fatalf("create second shared client: %v", err)
	}

	if firstClient.StatsKey == "" || secondClient.StatsKey == "" || firstClient.StatsKey == secondClient.StatsKey {
		t.Fatalf("expected unique stats keys, got first=%q second=%q", firstClient.StatsKey, secondClient.StatsKey)
	}
	if err := store.UpdateClientTraffic(ctx, firstClient.StatsKey, 7, 9); err != nil {
		t.Fatalf("update duplicate email traffic: %v", err)
	}
	inbounds, err := store.ListInbounds(ctx)
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	var matched int
	for _, inbound := range inbounds {
		for _, client := range inbound.Clients {
			if client.Email == "shared@example.com" {
				matched++
				if client.ID == firstClient.ID && (client.Up != 0 || client.Down != 0) {
					t.Fatalf("first sample should establish baseline without usage delta: %+v", client)
				}
				if client.ID == secondClient.ID && (client.Up != 0 || client.Down != 0) {
					t.Fatalf("duplicate email client should not be updated by another stats key: %+v", client)
				}
			}
		}
	}
	if matched != 2 {
		t.Fatalf("expected two duplicate-email clients, got %d", matched)
	}
}

func TestTrafficRawIncrementRollbackAndResetBaseline(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "traffic", Protocol: "vless", Port: 28083, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "meter@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if client.StatsKey == "" || client.StatsKey == client.Email {
		t.Fatalf("expected opaque stats key, got %+v", client)
	}
	t0 := time.Unix(100, 0)
	raw := func(up, down int64) []db.TrafficRawStat {
		return []db.TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: up, RawDown: down, Status: "ok"}}
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(100, 200), t0); err != nil {
		t.Fatalf("baseline sample: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(160, 260), t0.Add(10*time.Second)); err != nil {
		t.Fatalf("increment sample: %v", err)
	}
	states, err := store.ListTrafficStates(ctx)
	if err != nil {
		t.Fatalf("list states: %v", err)
	}
	state := findTrafficState(states, "xray", "client", client.StatsKey)
	if state == nil || state.TotalUp != 60 || state.TotalDown != 60 || state.RateUp != 6 || state.RateDown != 6 {
		t.Fatalf("unexpected increment state: %+v", state)
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(10, 20), t0.Add(20*time.Second)); err != nil {
		t.Fatalf("rollback sample: %v", err)
	}
	states, _ = store.ListTrafficStates(ctx)
	state = findTrafficState(states, "xray", "client", client.StatsKey)
	if state == nil || state.TotalUp != 60 || state.TotalDown != 60 {
		t.Fatalf("raw rollback should not reduce totals: %+v", state)
	}
	if _, err := store.ResetClientTrafficBaseline(ctx, client.ID, raw(10, 20)); err != nil {
		t.Fatalf("reset baseline: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(10, 20), t0.Add(30*time.Second)); err != nil {
		t.Fatalf("same raw after reset: %v", err)
	}
	inbounds, err := store.ListInbounds(ctx)
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	got := inbounds[0].Clients[0]
	if got.Up != 0 || got.Down != 0 {
		t.Fatalf("reset should not rebound on same raw baseline: %+v", got)
	}
}

func TestSingboxResetBaselineDoesNotReboundOldTraffic(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 28088, Network: "udp", Security: "tls"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "hy2@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	t0 := time.Unix(1000, 0)
	raw := func(up, down int64) []db.TrafficRawStat {
		return []db.TrafficRawStat{{Engine: "singbox", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: up, RawDown: down, Status: "ok"}}
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(1000, 2000), t0); err != nil {
		t.Fatalf("baseline sample: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(1500, 2600), t0.Add(10*time.Second)); err != nil {
		t.Fatalf("increment sample: %v", err)
	}
	if _, err := store.ResetClientTrafficBaseline(ctx, client.ID, raw(1500, 2600)); err != nil {
		t.Fatalf("reset baseline: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(1700, 2900), t0.Add(20*time.Second)); err != nil {
		t.Fatalf("post-reset sample: %v", err)
	}
	usage, found, err := store.GetClientTrafficUsageForClient(ctx, client.ID)
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	if !found || usage.Engine != "singbox" || usage.TotalUp != 200 || usage.TotalDown != 300 {
		t.Fatalf("expected only post-reset singbox delta, got found=%v usage=%+v", found, usage)
	}
}

func TestTrafficScopeStatusDoesNotPolluteRawBaseline(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "hy2-status", Protocol: "hysteria2", Port: 28095, Network: "udp", Security: "tls"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "hy2-status@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	inboundKey := "hy2-inbound-28095"
	raw := func(up, down int64) []db.TrafficRawStat {
		return []db.TrafficRawStat{
			{Engine: "singbox", ScopeType: "inbound", ScopeKey: inboundKey, RawUp: up, RawDown: down, Status: "ok"},
			{Engine: "singbox", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: up, RawDown: down, Status: "ok"},
		}
	}
	t0 := time.Unix(1000, 0)
	if err := store.ApplyTrafficRawStats(ctx, raw(1000, 2000), t0); err != nil {
		t.Fatalf("baseline sample: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(1100, 2300), t0.Add(10*time.Second)); err != nil {
		t.Fatalf("increment sample: %v", err)
	}
	samples, err := store.ListTrafficSamples(ctx, "client", time.Unix(0, 0), 100)
	if err != nil {
		t.Fatalf("list samples before marker: %v", err)
	}
	if len(samples) != 1 {
		t.Fatalf("expected one bucketed client sample before marker, got %+v", samples)
	}
	markerAt := t0.Add(20 * time.Second)
	if err := store.MarkTrafficScopeStatus(ctx, []db.TrafficStatusMarker{
		{Engine: "singbox", ScopeType: "inbound", ScopeKey: inboundKey, Status: "unsupported", Message: "stats unsupported"},
		{Engine: "singbox", ScopeType: "client", ScopeKey: client.StatsKey, Status: "unsupported", Message: "stats unsupported"},
	}, markerAt); err != nil {
		t.Fatalf("mark scope status: %v", err)
	}
	states, err := store.ListTrafficStates(ctx)
	if err != nil {
		t.Fatalf("list states: %v", err)
	}
	for _, scope := range []struct {
		scopeType string
		scopeKey  string
	}{
		{scopeType: "inbound", scopeKey: inboundKey},
		{scopeType: "client", scopeKey: client.StatsKey},
	} {
		state := findTrafficState(states, "singbox", scope.scopeType, scope.scopeKey)
		if state == nil {
			t.Fatalf("missing traffic state for %s/%s", scope.scopeType, scope.scopeKey)
		}
		if state.TotalUp != 100 || state.TotalDown != 300 || state.LastRawUp != 1100 || state.LastRawDown != 2300 {
			t.Fatalf("status marker polluted totals/raw for %s/%s: %+v", scope.scopeType, scope.scopeKey, state)
		}
		if state.Status != "unsupported" || state.Message != "stats unsupported" || state.LastSeenAt != markerAt.UTC().Format(time.RFC3339Nano) {
			t.Fatalf("status marker did not update status fields for %s/%s: %+v", scope.scopeType, scope.scopeKey, state)
		}
		if state.RateUp != 0 || state.RateDown != 0 {
			t.Fatalf("status marker should clear rates for %s/%s: %+v", scope.scopeType, scope.scopeKey, state)
		}
	}
	samples, err = store.ListTrafficSamples(ctx, "client", time.Unix(0, 0), 100)
	if err != nil {
		t.Fatalf("list samples after marker: %v", err)
	}
	if len(samples) != 2 || samples[1].TotalUp != 100 || samples[1].TotalDown != 300 || samples[1].RateUp != 0 || samples[1].RateDown != 0 || samples[1].Status != "unsupported" {
		t.Fatalf("status marker should write zero-rate sample without changing totals, got %+v", samples)
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(1200, 2600), t0.Add(30*time.Second)); err != nil {
		t.Fatalf("recovered sample: %v", err)
	}
	states, err = store.ListTrafficStates(ctx)
	if err != nil {
		t.Fatalf("list states after recovery: %v", err)
	}
	state := findTrafficState(states, "singbox", "client", client.StatsKey)
	if state == nil || state.TotalUp != 200 || state.TotalDown != 600 || state.LastRawUp != 1200 || state.LastRawDown != 2600 || state.RateUp != 0 || state.RateDown != 0 {
		t.Fatalf("recovered raw should add only incremental delta, got %+v", state)
	}
	samples, err = store.ListTrafficSamples(ctx, "client", time.Unix(0, 0), 100)
	if err != nil {
		t.Fatalf("list samples after recovery: %v", err)
	}
	if len(samples) != 2 || samples[1].TotalUp != 200 || samples[1].TotalDown != 600 || samples[1].RateUp != 0 || samples[1].RateDown != 0 || samples[1].Status != "ok" {
		t.Fatalf("expected one recovered client bucket after marker, got %+v", samples)
	}
}

func TestTrafficScopeStatusRefreshesXrayWaitingWithoutClearingTotals(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "xray-waiting", Protocol: "vless", Port: 28100, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "xray-waiting@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	inboundKey := db.GeneratedInboundTag(inbound)
	raw := func(up, down int64) []db.TrafficRawStat {
		return []db.TrafficRawStat{
			{Engine: "xray", ScopeType: "inbound", ScopeKey: inboundKey, RawUp: up, RawDown: down, Status: "ok"},
			{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: up, RawDown: down, Status: "ok"},
		}
	}
	t0 := time.Unix(2000, 0)
	if err := store.ApplyTrafficRawStats(ctx, raw(1000, 2000), t0); err != nil {
		t.Fatalf("baseline sample: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(1300, 2600), t0.Add(10*time.Second)); err != nil {
		t.Fatalf("increment sample: %v", err)
	}
	markerAt := t0.Add(10 * time.Minute)
	if err := store.MarkTrafficScopeStatus(ctx, []db.TrafficStatusMarker{
		{Engine: "xray", ScopeType: "inbound", ScopeKey: inboundKey, Status: "waiting", Message: "waiting for traffic sample"},
		{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, Status: "waiting", Message: "waiting for traffic sample"},
	}, markerAt); err != nil {
		t.Fatalf("mark waiting: %v", err)
	}
	states, err := store.ListTrafficStates(ctx)
	if err != nil {
		t.Fatalf("list states: %v", err)
	}
	for _, scope := range []struct {
		scopeType string
		scopeKey  string
	}{
		{scopeType: "inbound", scopeKey: inboundKey},
		{scopeType: "client", scopeKey: client.StatsKey},
	} {
		state := findTrafficState(states, "xray", scope.scopeType, scope.scopeKey)
		if state == nil {
			t.Fatalf("missing traffic state for %s/%s", scope.scopeType, scope.scopeKey)
		}
		if state.TotalUp != 300 || state.TotalDown != 600 || state.LastRawUp != 1300 || state.LastRawDown != 2600 {
			t.Fatalf("waiting marker should preserve totals/raw for %s/%s: %+v", scope.scopeType, scope.scopeKey, state)
		}
		if state.Status != "waiting" || state.Message != "waiting for traffic sample" || state.LastSeenAt != markerAt.UTC().Format(time.RFC3339Nano) {
			t.Fatalf("waiting marker did not refresh status fields for %s/%s: %+v", scope.scopeType, scope.scopeKey, state)
		}
		if state.RateUp != 0 || state.RateDown != 0 {
			t.Fatalf("waiting marker should clear rates for %s/%s: %+v", scope.scopeType, scope.scopeKey, state)
		}
	}
	samples, err := store.ListTrafficSamples(ctx, "client", time.Unix(0, 0), 100)
	if err != nil {
		t.Fatalf("list samples: %v", err)
	}
	if len(samples) != 2 || samples[1].TotalUp != 300 || samples[1].TotalDown != 600 || samples[1].RateUp != 0 || samples[1].RateDown != 0 || samples[1].Status != "waiting" {
		t.Fatalf("waiting marker should write zero-rate traffic sample without changing totals, got %+v", samples)
	}
}

func TestTrafficScopeStatusCreatesUnavailableStateWithoutTrafficHistory(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	observedAt := time.Unix(3000, 0)
	if err := store.MarkTrafficScopeStatus(ctx, []db.TrafficStatusMarker{
		{Engine: "xray", ScopeType: "inbound", ScopeKey: "inbound-1-vless", Status: "unavailable", Message: "stats offline"},
		{Engine: "xray", ScopeType: "client", ScopeKey: "c_new", Status: "unavailable", Message: "stats offline"},
	}, observedAt); err != nil {
		t.Fatalf("mark unavailable: %v", err)
	}
	states, err := store.ListTrafficStates(ctx)
	if err != nil {
		t.Fatalf("list states: %v", err)
	}
	for _, scope := range []struct {
		scopeType string
		scopeKey  string
	}{
		{scopeType: "inbound", scopeKey: "inbound-1-vless"},
		{scopeType: "client", scopeKey: "c_new"},
	} {
		state := findTrafficState(states, "xray", scope.scopeType, scope.scopeKey)
		if state == nil {
			t.Fatalf("missing unavailable state for %s/%s", scope.scopeType, scope.scopeKey)
		}
		if state.Status != "unavailable" || state.Message != "stats offline" || state.LastSeenAt != observedAt.UTC().Format(time.RFC3339Nano) {
			t.Fatalf("unexpected unavailable status for %s/%s: %+v", scope.scopeType, scope.scopeKey, state)
		}
		if state.TotalUp != 0 || state.TotalDown != 0 || state.LastRawUp != 0 || state.LastRawDown != 0 || state.RateUp != 0 || state.RateDown != 0 {
			t.Fatalf("new unavailable marker should create zero state for %s/%s: %+v", scope.scopeType, scope.scopeKey, state)
		}
	}
	samples, err := store.ListTrafficSamples(ctx, "client", time.Unix(0, 0), 100)
	if err != nil {
		t.Fatalf("list samples: %v", err)
	}
	if len(samples) != 1 || samples[0].ScopeKey != "c_new" || samples[0].TotalUp != 0 || samples[0].TotalDown != 0 || samples[0].RateUp != 0 || samples[0].RateDown != 0 || samples[0].Status != "unavailable" {
		t.Fatalf("unavailable marker should write zero-rate sample, got %+v", samples)
	}
}

func TestTrafficScopeStatusUnavailablePreservesTotalsAndRaw(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "xray-unavailable", Protocol: "vless", Port: 28104, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "xray-unavailable@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	t0 := time.Unix(4000, 0)
	raw := func(up, down int64) []db.TrafficRawStat {
		return []db.TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: up, RawDown: down, Status: "ok"}}
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(1000, 2000), t0); err != nil {
		t.Fatalf("baseline sample: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(1300, 2600), t0.Add(10*time.Second)); err != nil {
		t.Fatalf("increment sample: %v", err)
	}
	markerAt := t0.Add(time.Minute)
	if err := store.MarkTrafficScopeStatus(ctx, []db.TrafficStatusMarker{
		{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, Status: "unavailable", Message: "stats offline"},
	}, markerAt); err != nil {
		t.Fatalf("mark unavailable: %v", err)
	}
	states, err := store.ListTrafficStates(ctx)
	if err != nil {
		t.Fatalf("list states: %v", err)
	}
	state := findTrafficState(states, "xray", "client", client.StatsKey)
	if state == nil {
		t.Fatalf("missing unavailable client state")
	}
	if state.TotalUp != 300 || state.TotalDown != 600 || state.LastRawUp != 1300 || state.LastRawDown != 2600 {
		t.Fatalf("unavailable marker should preserve totals/raw, got %+v", state)
	}
	if state.RateUp != 0 || state.RateDown != 0 || state.Status != "unavailable" || state.Message != "stats offline" {
		t.Fatalf("unavailable marker should clear rate and refresh status, got %+v", state)
	}
	samples, err := store.ListTrafficSamples(ctx, "client", time.Unix(0, 0), 100)
	if err != nil {
		t.Fatalf("list samples: %v", err)
	}
	if len(samples) != 2 || samples[1].TotalUp != 300 || samples[1].TotalDown != 600 || samples[1].RateUp != 0 || samples[1].RateDown != 0 || samples[1].Status != "unavailable" {
		t.Fatalf("unavailable marker should write zero-rate sample preserving totals, got %+v", samples)
	}
}

func TestTrafficWaitingRecoverySuppressesCompressedRateAfterMultipleMarkers(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "xray-waiting-recovery", Protocol: "vless", Port: 28102, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "xray-waiting-recovery@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	raw := func(up, down int64) []db.TrafficRawStat {
		return []db.TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: up, RawDown: down, Status: "ok"}}
	}
	t0 := time.Unix(10_000, 0)
	if err := store.ApplyTrafficRawStats(ctx, raw(1000, 2000), t0); err != nil {
		t.Fatalf("baseline sample: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(1100, 2200), t0.Add(time.Minute)); err != nil {
		t.Fatalf("increment sample: %v", err)
	}
	for i := 2; i <= 5; i++ {
		if err := store.MarkTrafficScopeStatus(ctx, []db.TrafficStatusMarker{
			{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, Status: "waiting", Message: "waiting for traffic sample"},
		}, t0.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("waiting marker %d: %v", i, err)
		}
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(1600, 2800), t0.Add(5*time.Minute+10*time.Second)); err != nil {
		t.Fatalf("recovered raw sample: %v", err)
	}
	states, err := store.ListTrafficStates(ctx)
	if err != nil {
		t.Fatalf("list states: %v", err)
	}
	state := findTrafficState(states, "xray", "client", client.StatsKey)
	if state == nil || state.TotalUp != 600 || state.TotalDown != 800 || state.RateUp != 0 || state.RateDown != 0 || state.Status != "ok" {
		t.Fatalf("recovery should keep cumulative delta but suppress compressed rate, got %+v", state)
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(1660, 2920), t0.Add(6*time.Minute+10*time.Second)); err != nil {
		t.Fatalf("post-recovery raw sample: %v", err)
	}
	states, err = store.ListTrafficStates(ctx)
	if err != nil {
		t.Fatalf("list states after post-recovery: %v", err)
	}
	state = findTrafficState(states, "xray", "client", client.StatsKey)
	if state == nil || state.TotalUp != 660 || state.TotalDown != 920 || state.RateUp != 1 || state.RateDown != 2 {
		t.Fatalf("next raw sample should resume normal rate calculation, got %+v", state)
	}
	samples, err := store.ListTrafficSamples(ctx, "client", time.Unix(0, 0), 100)
	if err != nil {
		t.Fatalf("list samples: %v", err)
	}
	if len(samples) < 7 {
		t.Fatalf("expected baseline, waiting, recovery and post-recovery samples, got %+v", samples)
	}
	recovered := samples[len(samples)-2]
	if recovered.Status != "ok" || recovered.TotalUp != 600 || recovered.TotalDown != 800 || recovered.RateUp != 0 || recovered.RateDown != 0 {
		t.Fatalf("recovered series point should carry totals with zero rate, got %+v", recovered)
	}
}

func TestApplyTrafficRawStatsBatchesClientSamplesAndTotals(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	inboundA, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "batch-a", Protocol: "vless", Port: 28101, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound a: %v", err)
	}
	clientA, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inboundA.ID, Email: "batch-a@example.com"})
	if err != nil {
		t.Fatalf("create client a: %v", err)
	}
	inboundB, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "batch-b", Protocol: "vless", Port: 28102, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound b: %v", err)
	}
	clientB, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inboundB.ID, Email: "batch-b@example.com"})
	if err != nil {
		t.Fatalf("create client b: %v", err)
	}

	raw := func(aUp, aDown, bUp, bDown int64) []db.TrafficRawStat {
		return []db.TrafficRawStat{
			{Engine: "xray", ScopeType: "client", ScopeKey: clientA.StatsKey, RawUp: aUp, RawDown: aDown, Status: "ok"},
			{Engine: "xray", ScopeType: "client", ScopeKey: clientB.StatsKey, RawUp: bUp, RawDown: bDown, Status: "ok"},
			{Engine: "xray", ScopeType: "inbound", ScopeKey: "batch-inbound-a", RawUp: aUp, RawDown: aDown, Status: "ok"},
		}
	}
	t0 := time.Unix(2000, 0)
	if err := store.ApplyTrafficRawStats(ctx, raw(1000, 2000, 3000, 4000), t0); err != nil {
		t.Fatalf("baseline batch: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(1120, 2300, 3600, 4700), t0.Add(10*time.Second)); err != nil {
		t.Fatalf("increment batch: %v", err)
	}

	states, err := store.ListTrafficStates(ctx)
	if err != nil {
		t.Fatalf("list states: %v", err)
	}
	stateA := findTrafficState(states, "xray", "client", clientA.StatsKey)
	stateB := findTrafficState(states, "xray", "client", clientB.StatsKey)
	if stateA == nil || stateA.TotalUp != 120 || stateA.TotalDown != 300 || stateA.RateUp != 12 || stateA.RateDown != 30 {
		t.Fatalf("unexpected client a traffic state: %+v", stateA)
	}
	if stateB == nil || stateB.TotalUp != 600 || stateB.TotalDown != 700 || stateB.RateUp != 60 || stateB.RateDown != 70 {
		t.Fatalf("unexpected client b traffic state: %+v", stateB)
	}
	samples, err := store.ListTrafficSamples(ctx, "client", time.Unix(0, 0), 100)
	if err != nil {
		t.Fatalf("list samples: %v", err)
	}
	if len(samples) != 2 {
		t.Fatalf("expected one bucketed sample per client, got %+v", samples)
	}
	usage, found, err := store.GetClientTrafficUsageForClient(ctx, clientB.ID)
	if err != nil {
		t.Fatalf("get client b usage: %v", err)
	}
	if !found || usage.TotalUp != 600 || usage.TotalDown != 700 {
		t.Fatalf("expected client table to track expected-engine totals, found=%v usage=%+v", found, usage)
	}
}

func TestResetWithoutRawBaselineClearsExistingEngineAndUsesNextRawAsBaseline(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 28089, Network: "udp", Security: "tls"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "hy2-wait@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	raw := func(up, down int64) []db.TrafficRawStat {
		return []db.TrafficRawStat{{Engine: "singbox", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: up, RawDown: down, Status: "ok"}}
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(500, 700), time.Unix(100, 0)); err != nil {
		t.Fatalf("baseline sample: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(900, 1200), time.Unix(110, 0)); err != nil {
		t.Fatalf("increment sample: %v", err)
	}
	if _, err := store.ResetClientTrafficBaseline(ctx, client.ID, nil); err != nil {
		t.Fatalf("reset without baseline: %v", err)
	}
	states, err := store.ListTrafficStates(ctx)
	if err != nil {
		t.Fatalf("list states: %v", err)
	}
	state := findTrafficState(states, "singbox", "client", client.StatsKey)
	if state == nil || state.TotalUp != 0 || state.TotalDown != 0 || state.Status != "unavailable" {
		t.Fatalf("expected cleared unavailable singbox state, got %+v", state)
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(950, 1300), time.Unix(120, 0)); err != nil {
		t.Fatalf("first raw after missing baseline reset: %v", err)
	}
	usage, found, err := store.GetClientTrafficUsageForClient(ctx, client.ID)
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	if !found || usage.TotalUp != 0 || usage.TotalDown != 0 || usage.Status != "ok" {
		t.Fatalf("first raw after missing baseline should not rebound totals, got found=%v usage=%+v", found, usage)
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(1000, 1400), time.Unix(130, 0)); err != nil {
		t.Fatalf("second raw after reset: %v", err)
	}
	usage, found, err = store.GetClientTrafficUsageForClient(ctx, client.ID)
	if err != nil {
		t.Fatalf("usage after second raw: %v", err)
	}
	if !found || usage.TotalUp != 50 || usage.TotalDown != 100 {
		t.Fatalf("expected only post-baseline delta, got found=%v usage=%+v", found, usage)
	}
}

func TestFirstTrafficSamplePreservesLegacyClientTotals(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "legacy", Protocol: "vless", Port: 28084, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "legacy@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if err := store.UpdateClientTraffic(ctx, client.StatsKey, 100, 100); err != nil {
		t.Fatalf("baseline key sample: %v", err)
	}
	if err := store.UpdateClientTraffic(ctx, client.StatsKey, 150, 170); err != nil {
		t.Fatalf("increment key sample: %v", err)
	}
	loaded, err := store.ListInbounds(ctx)
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if loaded[0].Clients[0].Up != 50 || loaded[0].Clients[0].Down != 70 {
		t.Fatalf("expected prepared legacy totals, got %+v", loaded[0].Clients[0])
	}
	legacyClient := loaded[0].Clients[0]
	if err := store.ApplyTrafficRawStats(ctx, []db.TrafficRawStat{{Engine: "singbox", ScopeType: "client", ScopeKey: legacyClient.StatsKey, RawUp: 5, RawDown: 6, Status: "ok"}}, time.Unix(200, 0)); err != nil {
		t.Fatalf("first new engine sample: %v", err)
	}
	states, err := store.ListTrafficStates(ctx)
	if err != nil {
		t.Fatalf("list states: %v", err)
	}
	state := findTrafficState(states, "singbox", "client", legacyClient.StatsKey)
	if state == nil || state.TotalUp != 50 || state.TotalDown != 70 {
		t.Fatalf("first new state should preserve legacy totals: %+v", state)
	}
}

func TestLegacyEmailTrafficFallbackOnlyForUniqueEmail(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	firstInbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "first", Protocol: "vless", Port: 28085, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create first inbound: %v", err)
	}
	secondInbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "second", Protocol: "vless", Port: 28086, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create second inbound: %v", err)
	}
	unique, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: firstInbound.ID, Email: "unique@example.com"})
	if err != nil {
		t.Fatalf("create unique client: %v", err)
	}
	if _, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: firstInbound.ID, Email: "shared@example.com"}); err != nil {
		t.Fatalf("create first shared client: %v", err)
	}
	if _, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: secondInbound.ID, Email: "shared@example.com"}); err != nil {
		t.Fatalf("create second shared client: %v", err)
	}
	if err := store.UpdateClientTraffic(ctx, "unique@example.com", 10, 20); err != nil {
		t.Fatalf("legacy unique baseline: %v", err)
	}
	if err := store.UpdateClientTraffic(ctx, "unique@example.com", 15, 30); err != nil {
		t.Fatalf("legacy unique increment: %v", err)
	}
	if err := store.UpdateClientTraffic(ctx, "shared@example.com", 100, 200); err != nil {
		t.Fatalf("legacy duplicate should be ignored without error: %v", err)
	}
	inbounds, err := store.ListInbounds(ctx)
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	for _, inbound := range inbounds {
		for _, client := range inbound.Clients {
			if client.ID == unique.ID && (client.Up != 5 || client.Down != 10) {
				t.Fatalf("unique legacy email should map to stats_key: %+v", client)
			}
			if client.Email == "shared@example.com" && (client.Up != 0 || client.Down != 0) {
				t.Fatalf("duplicate legacy email should not be polluted: %+v", client)
			}
		}
	}
}

func TestClientTrafficWritebackUsesCurrentEngineOnly(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "engine", Protocol: "vless", Port: 28087, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "engine@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	xrayRaw := func(up, down int64) []db.TrafficRawStat {
		return []db.TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: up, RawDown: down, Status: "ok"}}
	}
	singboxRaw := func(up, down int64) []db.TrafficRawStat {
		return []db.TrafficRawStat{{Engine: "singbox", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: up, RawDown: down, Status: "ok"}}
	}
	if err := store.ApplyTrafficRawStats(ctx, xrayRaw(100, 100), time.Unix(100, 0)); err != nil {
		t.Fatalf("xray baseline: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, xrayRaw(150, 160), time.Unix(110, 0)); err != nil {
		t.Fatalf("xray increment: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, singboxRaw(1, 2), time.Unix(120, 0)); err != nil {
		t.Fatalf("singbox baseline: %v", err)
	}
	inbounds, err := store.ListInbounds(ctx)
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	got := inbounds[0].Clients[0]
	if got.Up != 50 || got.Down != 60 {
		t.Fatalf("singbox baseline must not overwrite xray client totals, got %+v", got)
	}
}

func TestGetClientTrafficUsageSelectsExpectedEngineWithoutDoubleCounting(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	xrayInbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "xray", Protocol: "vless", Port: 28090, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create xray inbound: %v", err)
	}
	singboxInbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 28091, Network: "udp", Security: "tls"})
	if err != nil {
		t.Fatalf("create singbox inbound: %v", err)
	}
	xrayClient, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: xrayInbound.ID, Email: "xray-usage"})
	if err != nil {
		t.Fatalf("create xray client: %v", err)
	}
	singboxClient, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: singboxInbound.ID, Email: "singbox-usage"})
	if err != nil {
		t.Fatalf("create singbox client: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, []db.TrafficRawStat{
		{Engine: "xray", ScopeType: "client", ScopeKey: xrayClient.StatsKey, RawUp: 10, RawDown: 10, Status: "ok"},
		{Engine: "singbox", ScopeType: "client", ScopeKey: xrayClient.StatsKey, RawUp: 100, RawDown: 100, Status: "ok"},
		{Engine: "xray", ScopeType: "client", ScopeKey: singboxClient.StatsKey, RawUp: 20, RawDown: 20, Status: "ok"},
		{Engine: "singbox", ScopeType: "client", ScopeKey: singboxClient.StatsKey, RawUp: 200, RawDown: 200, Status: "ok"},
	}, time.Unix(100, 0)); err != nil {
		t.Fatalf("baseline samples: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, []db.TrafficRawStat{
		{Engine: "xray", ScopeType: "client", ScopeKey: xrayClient.StatsKey, RawUp: 15, RawDown: 16, Status: "ok"},
		{Engine: "singbox", ScopeType: "client", ScopeKey: xrayClient.StatsKey, RawUp: 140, RawDown: 150, Status: "ok"},
		{Engine: "xray", ScopeType: "client", ScopeKey: singboxClient.StatsKey, RawUp: 25, RawDown: 26, Status: "ok"},
		{Engine: "singbox", ScopeType: "client", ScopeKey: singboxClient.StatsKey, RawUp: 230, RawDown: 240, Status: "ok"},
	}, time.Unix(110, 0)); err != nil {
		t.Fatalf("increment samples: %v", err)
	}
	xrayUsage, found, err := store.GetClientTrafficUsageForClient(ctx, xrayClient.ID)
	if err != nil {
		t.Fatalf("xray usage: %v", err)
	}
	if !found || xrayUsage.Engine != "xray" || xrayUsage.TotalUp != 5 || xrayUsage.TotalDown != 6 {
		t.Fatalf("expected xray usage only, got found=%v usage=%+v", found, xrayUsage)
	}
	singboxUsage, found, err := store.GetClientTrafficUsageForClient(ctx, singboxClient.ID)
	if err != nil {
		t.Fatalf("singbox usage: %v", err)
	}
	if !found || singboxUsage.Engine != "singbox" || singboxUsage.TotalUp != 30 || singboxUsage.TotalDown != 40 {
		t.Fatalf("expected singbox usage only, got found=%v usage=%+v", found, singboxUsage)
	}
}

func TestGetClientTrafficUsageUsesLegacyTotalsWhenNoTrafficState(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "legacy", Protocol: "vless", Port: 28092, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "legacy-usage"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, []db.TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: 100, RawDown: 100, Status: "ok"}}, time.Unix(100, 0)); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, []db.TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: 112, RawDown: 134, Status: "ok"}}, time.Unix(110, 0)); err != nil {
		t.Fatalf("increment: %v", err)
	}
	if err := store.DeleteClientTrafficStatesForTest(ctx, client.StatsKey); err != nil {
		t.Fatalf("delete traffic states: %v", err)
	}
	usage, found, err := store.GetClientTrafficUsageForClient(ctx, client.ID)
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	if !found || usage.Engine != "migate" || usage.Status != "cumulative_only" || usage.TotalUp != 12 || usage.TotalDown != 34 {
		t.Fatalf("expected legacy cumulative usage, got found=%v usage=%+v", found, usage)
	}
}

func TestGetClientTrafficUsageKeepsExpectedUnavailableOverFallbackOK(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 28093, Network: "udp", Security: "tls"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "hy2-unavailable"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, []db.TrafficRawStat{
		{Engine: "singbox", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: 100, RawDown: 100, Status: "ok"},
		{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: 1000, RawDown: 1000, Status: "ok"},
	}, time.Unix(100, 0)); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, []db.TrafficRawStat{
		{Engine: "singbox", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: 110, RawDown: 120, Status: "ok"},
		{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: 1300, RawDown: 1400, Status: "ok"},
	}, time.Unix(110, 0)); err != nil {
		t.Fatalf("increment: %v", err)
	}
	if err := store.MarkTrafficUnavailable(ctx, "singbox", "unavailable", "stats offline", time.Unix(120, 0)); err != nil {
		t.Fatalf("mark unavailable: %v", err)
	}
	usage, found, err := store.GetClientTrafficUsageForClient(ctx, client.ID)
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	if !found || usage.Engine != "singbox" || usage.Status != "unavailable" || usage.TotalUp != 10 || usage.TotalDown != 20 {
		t.Fatalf("expected unavailable singbox usage, got found=%v usage=%+v", found, usage)
	}
}

func TestGetClientTrafficUsageFallsBackWhenExpectedEngineMissing(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 28094, Network: "udp", Security: "tls"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "hy2-fallback"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, []db.TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: 100, RawDown: 100, Status: "ok"}}, time.Unix(100, 0)); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, []db.TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: 130, RawDown: 140, Status: "ok"}}, time.Unix(110, 0)); err != nil {
		t.Fatalf("increment: %v", err)
	}
	usage, found, err := store.GetClientTrafficUsageForClient(ctx, client.ID)
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	if !found || usage.Engine != "xray" || usage.Status != "ok" || usage.TotalUp != 30 || usage.TotalDown != 40 {
		t.Fatalf("expected xray fallback usage, got found=%v usage=%+v", found, usage)
	}
}

func TestCertificateAssetsAndInboundUsage(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "tls", Protocol: "vless", Port: 28100, Network: "tcp", Security: "tls", TLSSNI: "custom.example.com"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	emptySNIInbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "tls-empty-sni", Protocol: "vless", Port: 28101, Network: "ws", Security: "tls"})
	if err != nil {
		t.Fatalf("create empty sni inbound: %v", err)
	}
	customHostInbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "tls-custom-host", Protocol: "vless", Port: 28102, Network: "h2", Security: "tls", TLSSNI: "old.example.com", WsHost: "cdn.example.com"})
	if err != nil {
		t.Fatalf("create custom host inbound: %v", err)
	}
	cert, err := store.UpsertCertificate(ctx, db.UpsertCertificateParams{
		Name:             "example.com",
		Source:           db.CertSourceACME,
		Status:           db.CertStatusIssued,
		Domains:          []string{"example.com", "www.example.com"},
		CertPath:         "/etc/migate/certs/example/fullchain.pem",
		KeyPath:          "/etc/migate/certs/example/privkey.pem",
		NotBefore:        "2026-06-20T00:00:00Z",
		NotAfter:         "2026-09-20T00:00:00Z",
		Fingerprint:      "ABC",
		Serial:           "123",
		IssueEmail:       "ops@example.com",
		ACMEDirectoryURL: "https://acme.example/directory",
		ChallengeMethod:  "http-01",
	})
	if err != nil {
		t.Fatalf("upsert certificate: %v", err)
	}
	if _, err := store.RecordCertificateOperation(ctx, db.CertificateOperation{CertificateID: cert.ID, Type: "import", Status: "success"}); err != nil {
		t.Fatalf("record operation: %v", err)
	}
	updated, err := store.ApplyCertificateToInbounds(ctx, cert, []int64{inbound.ID, emptySNIInbound.ID, customHostInbound.ID})
	if err != nil {
		t.Fatalf("apply certificate: %v", err)
	}
	if len(updated) != 3 || updated[0].TLSCertFile != cert.CertPath || updated[0].TLSKeyFile != cert.KeyPath || updated[0].TLSSNI != "example.com" || updated[1].TLSSNI != "example.com" {
		t.Fatalf("unexpected applied inbound: %#v", updated)
	}
	if updated[0].WsHost != "" {
		t.Fatalf("non WS/H2 inbound ws_host = %q, want empty", updated[0].WsHost)
	}
	if updated[1].WsHost != "example.com" {
		t.Fatalf("WS inbound ws_host = %q, want example.com", updated[1].WsHost)
	}
	if updated[2].TLSSNI != "example.com" || updated[2].WsHost != "cdn.example.com" {
		t.Fatalf("custom WS/H2 host should be preserved, got %#v", updated[2])
	}
	loaded, err := store.GetCertificate(ctx, cert.ID)
	if err != nil {
		t.Fatalf("get certificate: %v", err)
	}
	if loaded.UsageCount != 3 || len(loaded.Usages) != 3 || len(loaded.Domains) != 2 || loaded.IssueEmail != "ops@example.com" || loaded.ACMEDirectoryURL == "" || loaded.ChallengeMethod != "http-01" {
		t.Fatalf("unexpected usage metadata: %#v", loaded)
	}
	ops, err := store.ListCertificateOperations(ctx, cert.ID, 10)
	if err != nil {
		t.Fatalf("list operations: %v", err)
	}
	if len(ops) != 1 || ops[0].Type != "import" {
		t.Fatalf("unexpected operations: %#v", ops)
	}
}

func findTrafficState(states []db.TrafficState, engine, scopeType, scopeKey string) *db.TrafficState {
	for i := range states {
		if states[i].Engine == engine && states[i].ScopeType == scopeType && states[i].ScopeKey == scopeKey {
			return &states[i]
		}
	}
	return nil
}
