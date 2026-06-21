package scheduler

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/imzyb/MiGate/internal/db"
)

type OutboundSubscriptionStore interface {
	ListOutboundSubscriptions(ctx context.Context) ([]db.OutboundSubscription, error)
}

type OutboundSubscriptionRefresher interface {
	RefreshOutboundSubscription(ctx context.Context, id int64) error
}

type OutboundSubscriptionScheduler struct {
	store     OutboundSubscriptionStore
	refresher OutboundSubscriptionRefresher
	interval  time.Duration
	now       func() time.Time
	ctx       context.Context
	cancel    context.CancelFunc
	stopped   bool
	mu        sync.Mutex
}

func NewOutboundSubscriptionScheduler(store OutboundSubscriptionStore, refresher OutboundSubscriptionRefresher, interval time.Duration) *OutboundSubscriptionScheduler {
	if interval <= 0 {
		interval = time.Minute
	}
	return &OutboundSubscriptionScheduler{store: store, refresher: refresher, interval: interval, now: time.Now}
}

func (s *OutboundSubscriptionScheduler) Start() {
	s.mu.Lock()
	s.ctx, s.cancel = context.WithCancel(context.Background())
	if s.stopped {
		s.cancel()
	}
	s.mu.Unlock()

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	s.sync()
	for {
		select {
		case <-s.ctx.Done():
			log.Println("outbound subscription scheduler stopped")
			return
		case <-ticker.C:
			s.sync()
		}
	}
}

func (s *OutboundSubscriptionScheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = true
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *OutboundSubscriptionScheduler) sync() {
	if s.store == nil || s.refresher == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	subs, err := s.store.ListOutboundSubscriptions(ctx)
	if err != nil {
		log.Printf("outbound subscription scheduler: list failed: %v", err)
		return
	}
	now := s.now().UTC()
	for _, sub := range subs {
		if !subscriptionRefreshDue(sub, now) {
			continue
		}
		if err := s.refresher.RefreshOutboundSubscription(ctx, sub.ID); err != nil {
			log.Printf("outbound subscription scheduler: refresh %d failed: %v", sub.ID, err)
			continue
		}
		log.Printf("outbound subscription scheduler: refreshed %d", sub.ID)
	}
}

func subscriptionRefreshDue(sub db.OutboundSubscription, now time.Time) bool {
	if !sub.Enabled {
		return false
	}
	intervalSeconds := sub.UpdateIntervalSeconds
	if intervalSeconds <= 0 {
		intervalSeconds = db.DefaultOutboundSubscriptionUpdateIntervalSeconds
	}
	base := parseRFC3339(sub.LastAttemptAt)
	if base.IsZero() {
		base = parseRFC3339(sub.LastFetchedAt)
	}
	if base.IsZero() {
		return true
	}
	return !base.Add(time.Duration(intervalSeconds) * time.Second).After(now)
}

func parseRFC3339(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}
