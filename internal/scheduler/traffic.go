package scheduler

import (
	"context"
	"log"
	"time"

	"github.com/imzyb/MiGate/internal/xray"
)

// Store is the subset of db.Store methods needed by the scheduler.
type Store interface {
	UpdateClientTraffic(ctx context.Context, email string, uplink, downlink int64) error
}

// TrafficSyncScheduler periodically syncs traffic statistics from Xray to the database.
type TrafficSyncScheduler struct {
	store       Store
	statsClient xray.StatsClient
	interval    time.Duration
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewTrafficSyncScheduler creates a new scheduler.
// interval: how often to sync (e.g., 1 * time.Minute)
func NewTrafficSyncScheduler(store Store, statsClient xray.StatsClient, interval time.Duration) *TrafficSyncScheduler {
	return &TrafficSyncScheduler{
		store:       store,
		statsClient: statsClient,
		interval:    interval,
	}
}

// Start begins the periodic sync loop.
// This is a blocking call - run it in a separate goroutine.
func (s *TrafficSyncScheduler) Start() {
	s.ctx, s.cancel = context.WithCancel(context.Background())

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	// Run once immediately on start
	s.sync()

	for {
		select {
		case <-s.ctx.Done():
			log.Println("traffic sync scheduler stopped")
			return
		case <-ticker.C:
			s.sync()
		}
	}
}

// Stop stops the scheduler.
func (s *TrafficSyncScheduler) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

// sync performs a single sync cycle: query Xray stats and update DB.
func (s *TrafficSyncScheduler) sync() {
	ctx, timeout := context.WithTimeout(context.Background(), 10*time.Second)
	defer timeout()

	stats, err := s.statsClient.QueryAllStats(ctx)
	if err != nil {
		log.Printf("traffic sync: failed to query stats: %v", err)
		return
	}

	// Update database for each client
	for email, clientStats := range stats {
		err := s.store.UpdateClientTraffic(ctx, email, clientStats.Uplink, clientStats.Downlink)
		if err != nil {
			log.Printf("traffic sync: failed to update client %s: %v", email, err)
		}
	}

	log.Printf("traffic sync: updated %d clients", len(stats))
}
