package scheduler

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/singbox"
	"github.com/imzyb/MiGate/internal/xray"
)

// Store is the subset of db.Store methods needed by the scheduler.
type Store interface {
	UpdateClientTraffic(ctx context.Context, email string, uplink, downlink int64) error
	ApplyTrafficRawStats(ctx context.Context, stats []db.TrafficRawStat, observedAt time.Time) error
	MarkTrafficScopeStatus(ctx context.Context, stats []db.TrafficStatusMarker, observedAt time.Time) error
	MarkTrafficUnavailable(ctx context.Context, engine, status, message string, observedAt time.Time) error
}

type inboundStore interface {
	ListInbounds(ctx context.Context) ([]db.Inbound, error)
}

// TrafficSyncScheduler periodically syncs traffic statistics from Xray to the database.
type TrafficSyncScheduler struct {
	store              Store
	statsClient        xray.StatsClient
	singboxStatsClient singbox.StatsClient
	singboxInbounds    []db.Inbound
	singboxCapability  func(context.Context) singbox.Capability
	newSingboxStats    func(context.Context) (singbox.StatsClient, error)
	interval           time.Duration
	ctx                context.Context
	cancel             context.CancelFunc
	stopped            bool
	mu                 sync.Mutex
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

func NewTrafficSyncSchedulerWithSingbox(store Store, statsClient xray.StatsClient, singboxStatsClient singbox.StatsClient, interval time.Duration) *TrafficSyncScheduler {
	scheduler := NewTrafficSyncScheduler(store, statsClient, interval)
	scheduler.singboxStatsClient = singboxStatsClient
	return scheduler
}

func NewTrafficSyncSchedulerWithSingboxConfig(store Store, statsClient xray.StatsClient, singboxStatsClient singbox.StatsClient, singboxInbounds []db.Inbound, interval time.Duration) *TrafficSyncScheduler {
	scheduler := NewTrafficSyncSchedulerWithSingbox(store, statsClient, singboxStatsClient, interval)
	scheduler.singboxInbounds = singboxInbounds
	return scheduler
}

// Start begins the periodic sync loop.
// This is a blocking call - run it in a separate goroutine.
func (s *TrafficSyncScheduler) Start() {
	s.mu.Lock()
	s.ctx, s.cancel = context.WithCancel(context.Background())
	if s.stopped {
		s.cancel()
	}
	s.mu.Unlock()

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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = true
	if s.cancel != nil {
		s.cancel()
	}
}

// sync performs a single sync cycle: query Xray stats and update DB.
func (s *TrafficSyncScheduler) sync() {
	ctx, timeout := context.WithTimeout(context.Background(), 10*time.Second)
	defer timeout()
	observedAt := time.Now().UTC()

	rawStats := []db.TrafficRawStat{}
	if s.statsClient != nil {
		stats, err := s.statsClient.QueryTrafficStats(ctx)
		if err != nil {
			log.Printf("traffic sync: failed to query xray stats: %v", err)
			if markers, refreshed := s.xrayTrafficStatusMarkers(ctx, nil, "unavailable", err.Error(), false); refreshed && len(markers) > 0 {
				if err := s.store.MarkTrafficScopeStatus(ctx, markers, observedAt); err != nil {
					log.Printf("traffic sync: failed to apply xray unavailable markers: %v", err)
				}
			}
			_ = s.store.MarkTrafficUnavailable(ctx, "xray", "unavailable", err.Error(), observedAt)
		} else {
			xrayRawStats := convertRawStats(stats)
			if markers, refreshed := s.xrayTrafficStatusMarkers(ctx, xrayRawStats, "waiting", "waiting for traffic sample", false); refreshed && len(markers) > 0 {
				if err := s.store.MarkTrafficScopeStatus(ctx, markers, observedAt); err != nil {
					log.Printf("traffic sync: failed to apply xray waiting markers: %v", err)
				}
			}
			rawStats = append(rawStats, xrayRawStats...)
		}
	}
	if s.singboxStatsClient != nil {
		client := s.singboxStatsClient
		if disabled, ok := client.(*singbox.DisabledStatsClient); ok {
			client = s.refreshDisabledSingboxStatsClient(ctx, disabled)
		}
		if disabled, ok := client.(*singbox.DisabledStatsClient); ok {
			status := disabled.Status
			if status == "" {
				status = "not_configured"
			}
			inbounds, refreshed := s.currentSingboxInbounds(ctx)
			if refreshed && len(inbounds) > 0 {
				markers := singboxTrafficStatusMarkers(inbounds, status, disabled.Message)
				if len(markers) > 0 {
					if err := s.store.MarkTrafficScopeStatus(ctx, markers, observedAt); err != nil {
						log.Printf("traffic sync: failed to apply sing-box status markers: %v", err)
					}
				}
			}
			_ = s.store.MarkTrafficUnavailable(ctx, "singbox", status, disabled.Message, observedAt)
		} else {
			stats, err := client.QueryTrafficStats(ctx)
			if err != nil {
				log.Printf("traffic sync: failed to query sing-box stats: %v", err)
				inbounds, refreshed := s.currentSingboxInbounds(ctx)
				if refreshed && len(inbounds) > 0 {
					markers := singboxTrafficStatusMarkersForScopes(inbounds, "unavailable", err.Error(), false)
					if len(markers) > 0 {
						if err := s.store.MarkTrafficScopeStatus(ctx, markers, observedAt); err != nil {
							log.Printf("traffic sync: failed to apply sing-box unavailable markers: %v", err)
						}
					}
				}
				_ = s.store.MarkTrafficUnavailable(ctx, "singbox", "unavailable", err.Error(), observedAt)
			} else {
				rawStats = append(rawStats, convertRawStats(stats)...)
			}
		}
	}
	if len(rawStats) > 0 {
		if err := s.store.ApplyTrafficRawStats(ctx, rawStats, observedAt); err != nil {
			log.Printf("traffic sync: failed to apply traffic states: %v", err)
			return
		}
		log.Printf("traffic sync: applied %d traffic counters", len(rawStats))
	}
}

func (s *TrafficSyncScheduler) currentSingboxInbounds(ctx context.Context) ([]db.Inbound, bool) {
	if store, ok := s.store.(inboundStore); ok {
		inbounds, err := store.ListInbounds(ctx)
		if err == nil {
			s.singboxInbounds = inbounds
			return inbounds, true
		}
		log.Printf("traffic sync: failed to refresh sing-box inbounds: %v", err)
		return s.singboxInbounds, false
	}
	return s.singboxInbounds, true
}

func (s *TrafficSyncScheduler) refreshDisabledSingboxStatsClient(ctx context.Context, disabled *singbox.DisabledStatsClient) singbox.StatsClient {
	if disabled.Status != "not_configured" {
		return disabled
	}
	inbounds, refreshed := s.currentSingboxInbounds(ctx)
	if !refreshed {
		return disabled
	}
	if !singbox.HasEnabledSingboxInbound(inbounds) {
		return disabled
	}
	detect := s.singboxCapability
	if detect == nil {
		detect = singbox.DetectCapability
	}
	capability := detect(ctx)
	var client singbox.StatsClient
	switch {
	case capability.V2RayAPIStats:
		buildClient := s.newSingboxStats
		if buildClient == nil {
			buildClient = func(ctx context.Context) (singbox.StatsClient, error) {
				return singbox.NewGRPCStatsClient(ctx, "127.0.0.1:10086")
			}
		}
		grpcClient, err := buildClient(ctx)
		if err != nil {
			client = singbox.NewUnavailableStatsClient(fmt.Errorf("build sing-box stats client: %w", err))
		} else {
			client = grpcClient
		}
	case capability.Unsupported:
		client = singbox.NewDisabledStatsClient("unsupported", singbox.StatsUnsupportedMessage)
	default:
		message := capability.Message
		if message == "" {
			message = "sing-box stats capability check failed"
		}
		client = singbox.NewUnavailableStatsClient(fmt.Errorf("%s", message))
	}
	s.singboxStatsClient = client
	return client
}

func (s *TrafficSyncScheduler) xrayTrafficStatusMarkers(ctx context.Context, observed []db.TrafficRawStat, status, message string, includeInbounds bool) ([]db.TrafficStatusMarker, bool) {
	store, ok := s.store.(inboundStore)
	if !ok {
		return nil, false
	}
	inbounds, err := store.ListInbounds(ctx)
	if err != nil {
		log.Printf("traffic sync: failed to refresh xray inbounds: %v", err)
		return nil, false
	}
	return xrayMissingTrafficStatusMarkers(inbounds, observed, status, message, includeInbounds), true
}

func xrayMissingTrafficStatusMarkers(inbounds []db.Inbound, observed []db.TrafficRawStat, status, message string, includeInbounds bool) []db.TrafficStatusMarker {
	seen := map[string]map[string]bool{}
	for _, stat := range observed {
		if normalizeTrafficToken(stat.Engine) != "xray" {
			continue
		}
		scopeType := normalizeTrafficToken(stat.ScopeType)
		scopeKey := strings.TrimSpace(stat.ScopeKey)
		if scopeType == "" || scopeKey == "" {
			continue
		}
		byKey := seen[scopeType]
		if byKey == nil {
			byKey = map[string]bool{}
			seen[scopeType] = byKey
		}
		byKey[scopeKey] = true
	}
	markers := []db.TrafficStatusMarker{}
	for _, inbound := range inbounds {
		if !inbound.Enabled || db.InboundCore(inbound) != db.CoreXray {
			continue
		}
		if includeInbounds {
			inboundKey := db.GeneratedInboundTag(inbound)
			if inboundKey != "" && !seen["inbound"][inboundKey] {
				markers = append(markers, db.TrafficStatusMarker{Engine: "xray", ScopeType: "inbound", ScopeKey: inboundKey, Status: status, Message: message})
			}
		}
		for _, client := range inbound.Clients {
			if !client.Enabled {
				continue
			}
			clientKey := strings.TrimSpace(client.StatsKey)
			if clientKey == "" {
				clientKey = strings.TrimSpace(client.Email)
			}
			if clientKey == "" {
				continue
			}
			if seen["client"][clientKey] {
				continue
			}
			markers = append(markers, db.TrafficStatusMarker{Engine: "xray", ScopeType: "client", ScopeKey: clientKey, Status: status, Message: message})
		}
	}
	return markers
}

func normalizeTrafficToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "sing-box" {
		return "singbox"
	}
	return value
}

func singboxTrafficStatusMarkers(inbounds []db.Inbound, status, message string) []db.TrafficStatusMarker {
	return singboxTrafficStatusMarkersForScopes(inbounds, status, message, true)
}

func singboxTrafficStatusMarkersForScopes(inbounds []db.Inbound, status, message string, includeInbounds bool) []db.TrafficStatusMarker {
	markers := []db.TrafficStatusMarker{}
	for _, inbound := range inbounds {
		if !inbound.Enabled || !singbox.IsSingboxProtocol(inbound.Protocol) {
			continue
		}
		if includeInbounds {
			inboundKey := singbox.InboundStatsTag(inbound)
			markers = append(markers, db.TrafficStatusMarker{Engine: "singbox", ScopeType: "inbound", ScopeKey: inboundKey, Status: status, Message: message})
		}
		for _, client := range inbound.Clients {
			if !client.Enabled {
				continue
			}
			clientKey := singbox.UserStatsKey(client)
			if clientKey == "" {
				continue
			}
			markers = append(markers, db.TrafficStatusMarker{Engine: "singbox", ScopeType: "client", ScopeKey: clientKey, Status: status, Message: message})
		}
	}
	return markers
}

func convertRawStats(stats []xray.TrafficStat) []db.TrafficRawStat {
	raw := make([]db.TrafficRawStat, 0, len(stats))
	for _, stat := range stats {
		raw = append(raw, db.TrafficRawStat{
			Engine: stat.Engine, ScopeType: stat.ScopeType, ScopeKey: stat.ScopeKey,
			RawUp: stat.Uplink, RawDown: stat.Downlink, Status: "ok",
		})
	}
	return raw
}
