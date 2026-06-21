package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/imzyb/MiGate/internal/db"
)

func TestOutboundSubscriptionSchedulerRefreshesOnlyDueEnabledSubscriptions(t *testing.T) {
	now := time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)
	store := &fakeOutboundSubscriptionStore{subs: []db.OutboundSubscription{
		{ID: 1, Enabled: true, UpdateIntervalSeconds: 600},
		{ID: 2, Enabled: true, UpdateIntervalSeconds: 600, LastFetchedAt: now.Add(-5 * time.Minute).Format(time.RFC3339)},
		{ID: 3, Enabled: false, UpdateIntervalSeconds: 600},
		{ID: 4, Enabled: true, UpdateIntervalSeconds: 600, LastAttemptAt: now.Add(-11 * time.Minute).Format(time.RFC3339)},
		{ID: 5, Enabled: true, UpdateIntervalSeconds: 600, LastAttemptAt: now.Add(-1 * time.Minute).Format(time.RFC3339), LastFetchedAt: now.Add(-20 * time.Minute).Format(time.RFC3339)},
	}}
	refresher := &fakeOutboundSubscriptionRefresher{}
	scheduler := NewOutboundSubscriptionScheduler(store, refresher, time.Minute)
	scheduler.now = func() time.Time { return now }

	scheduler.sync()

	if got, want := refresher.ids, []int64{1, 4}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("unexpected refreshed subscriptions: got=%v want=%v", got, want)
	}
}

func TestSubscriptionRefreshDueUsesLastFetchedWhenAttemptMissing(t *testing.T) {
	now := time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)
	if !subscriptionRefreshDue(db.OutboundSubscription{Enabled: true, UpdateIntervalSeconds: 60, LastFetchedAt: now.Add(-time.Minute).Format(time.RFC3339)}, now) {
		t.Fatal("expected subscription at exact interval boundary to be due")
	}
	if subscriptionRefreshDue(db.OutboundSubscription{Enabled: true, UpdateIntervalSeconds: 60, LastFetchedAt: now.Add(-59 * time.Second).Format(time.RFC3339)}, now) {
		t.Fatal("expected subscription before interval boundary to be skipped")
	}
}

func TestSubscriptionRefreshDueUsesDefaultIntervalWhenMissing(t *testing.T) {
	now := time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)
	if subscriptionRefreshDue(db.OutboundSubscription{Enabled: true, LastFetchedAt: now.Add(-6*time.Hour + time.Second).Format(time.RFC3339)}, now) {
		t.Fatal("expected subscription before default interval boundary to be skipped")
	}
	if !subscriptionRefreshDue(db.OutboundSubscription{Enabled: true, LastFetchedAt: now.Add(-6 * time.Hour).Format(time.RFC3339)}, now) {
		t.Fatal("expected subscription at default interval boundary to be due")
	}
}

type fakeOutboundSubscriptionStore struct {
	subs []db.OutboundSubscription
}

func (s *fakeOutboundSubscriptionStore) ListOutboundSubscriptions(context.Context) ([]db.OutboundSubscription, error) {
	return s.subs, nil
}

type fakeOutboundSubscriptionRefresher struct {
	ids []int64
}

func (r *fakeOutboundSubscriptionRefresher) RefreshOutboundSubscription(_ context.Context, id int64) error {
	r.ids = append(r.ids, id)
	return nil
}
