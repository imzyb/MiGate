package web_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/web"
)

func TestRefreshOutboundSubscriptionHTTPReturnsAcceptedImmediately(t *testing.T) {
	store := openWebTestStore(t)
	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "xray", Protocol: "vless", Port: 2551, Network: "tcp", Security: "none"}); err != nil {
		t.Fatalf("create xray inbound: %v", err)
	}
	sub, err := store.CreateOutboundSubscription(context.Background(), db.CreateOutboundSubscriptionParams{Remark: "sub", URL: "https://example.com/sub", Enabled: true, AllowPrivate: true})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		_, _ = w.Write([]byte("trojan://secret@example.com:443#node"))
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})
	if _, err := store.UpdateOutboundSubscription(context.Background(), sub.ID, db.UpdateOutboundSubscriptionParams{Remark: "sub", URL: server.URL, Enabled: true, AllowPrivate: true}); err != nil {
		t.Fatalf("update subscription url: %v", err)
	}
	router := web.NewRouter(web.WithAutoCoreApply(false), web.WithStore(store), web.WithXrayController(&fakeXrayController{}))

	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/outbound-subscriptions/"+strconv.FormatInt(sub.ID, 10)+"/refresh", nil))
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("refresh request did not start background fetch")
	}
	select {
	case <-done:
	case <-time.After(150 * time.Millisecond):
		t.Fatal("refresh endpoint waited for subscription fetch; expected async 202 response")
	}
	if response.Code != http.StatusAccepted {
		t.Fatalf("expected async refresh 202, got %d: %s", response.Code, response.Body.String())
	}
	for _, want := range []string{`"status":"queued"`, `"subscription_id"`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("async refresh response missing %q: %s", want, response.Body.String())
		}
	}
}

func strconvFormatInt(id int64) string { return strconv.FormatInt(id, 10) }
